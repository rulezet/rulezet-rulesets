rule TTP_XOR_WriteProcessMemory_5b9d {
  strings:
    $key_5b9d = { 0c ef [2] 3e cd [2] 38 f8 [2] 16 f8 [2] 29 e4 }

  condition:
    any of them
}