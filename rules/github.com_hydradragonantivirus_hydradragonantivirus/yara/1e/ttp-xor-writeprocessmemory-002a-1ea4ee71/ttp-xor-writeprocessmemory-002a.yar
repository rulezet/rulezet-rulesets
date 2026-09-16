rule TTP_XOR_WriteProcessMemory_002a {
  strings:
    $key_002a = { 57 58 [2] 65 7a [2] 63 4f [2] 4d 4f [2] 72 53 }

  condition:
    any of them
}