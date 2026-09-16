rule TTP_XOR_WriteProcessMemory_0ae6 {
  strings:
    $key_0ae6 = { 5d 94 [2] 6f b6 [2] 69 83 [2] 47 83 [2] 78 9f }

  condition:
    any of them
}