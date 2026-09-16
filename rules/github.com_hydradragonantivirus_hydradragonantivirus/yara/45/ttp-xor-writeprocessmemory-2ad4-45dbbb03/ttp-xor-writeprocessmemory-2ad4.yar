rule TTP_XOR_WriteProcessMemory_2ad4 {
  strings:
    $key_2ad4 = { 7d a6 [2] 4f 84 [2] 49 b1 [2] 67 b1 [2] 58 ad }

  condition:
    any of them
}