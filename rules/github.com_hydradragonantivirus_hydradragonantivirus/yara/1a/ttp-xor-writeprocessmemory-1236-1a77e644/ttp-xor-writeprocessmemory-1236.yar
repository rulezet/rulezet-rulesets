rule TTP_XOR_WriteProcessMemory_1236 {
  strings:
    $key_1236 = { 45 44 [2] 77 66 [2] 71 53 [2] 5f 53 [2] 60 4f }

  condition:
    any of them
}