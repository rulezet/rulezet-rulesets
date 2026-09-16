rule TTP_XOR_WriteProcessMemory_05df {
  strings:
    $key_05df = { 52 ad [2] 60 8f [2] 66 ba [2] 48 ba [2] 77 a6 }

  condition:
    any of them
}