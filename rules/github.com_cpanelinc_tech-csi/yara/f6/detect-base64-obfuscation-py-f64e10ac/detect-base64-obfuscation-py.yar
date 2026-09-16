rule Detect_Base64_Obfuscation_Py {
    meta:
      description = "Detects obfuscated Python code that uses base64 decoding"
      author = "tgould@cadosecurity.com"
      date = "2024-09-04"
    strings:
      $import_base64 = "import base64" ascii
      $exec_base64_decode = "exec(base64.b64decode(" ascii
      $decode_exec = "base64.b64decode(b).decode())" ascii

    condition:
      all of ($import_base64, $exec_base64_decode, $decode_exec)
}