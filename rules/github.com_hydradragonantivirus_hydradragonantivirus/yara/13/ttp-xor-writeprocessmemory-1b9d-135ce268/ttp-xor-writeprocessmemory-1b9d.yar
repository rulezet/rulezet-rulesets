rule TTP_XOR_WriteProcessMemory_1b9d {
  strings:
    $key_1b9d = { 4c ef [2] 7e cd [2] 78 f8 [2] 56 f8 [2] 69 e4 }

  condition:
    any of them
}