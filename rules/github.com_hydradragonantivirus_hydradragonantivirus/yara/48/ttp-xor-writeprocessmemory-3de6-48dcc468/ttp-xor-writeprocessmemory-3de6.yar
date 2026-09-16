rule TTP_XOR_WriteProcessMemory_3de6 {
  strings:
    $key_3de6 = { 6a 94 [2] 58 b6 [2] 5e 83 [2] 70 83 [2] 4f 9f }

  condition:
    any of them
}