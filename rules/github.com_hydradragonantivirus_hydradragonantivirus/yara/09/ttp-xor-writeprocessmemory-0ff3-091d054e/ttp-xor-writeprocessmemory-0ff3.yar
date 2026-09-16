rule TTP_XOR_WriteProcessMemory_0ff3 {
  strings:
    $key_0ff3 = { 58 81 [2] 6a a3 [2] 6c 96 [2] 42 96 [2] 7d 8a }

  condition:
    any of them
}