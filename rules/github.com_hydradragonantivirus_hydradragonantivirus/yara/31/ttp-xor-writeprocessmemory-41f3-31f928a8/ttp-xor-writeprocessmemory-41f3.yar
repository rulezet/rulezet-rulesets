rule TTP_XOR_WriteProcessMemory_41f3 {
  strings:
    $key_41f3 = { 16 81 [2] 24 a3 [2] 22 96 [2] 0c 96 [2] 33 8a }

  condition:
    any of them
}