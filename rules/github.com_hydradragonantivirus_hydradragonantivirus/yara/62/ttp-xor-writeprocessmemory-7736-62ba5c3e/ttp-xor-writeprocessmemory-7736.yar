rule TTP_XOR_WriteProcessMemory_7736 {
  strings:
    $key_7736 = { 20 44 [2] 12 66 [2] 14 53 [2] 3a 53 [2] 05 4f }

  condition:
    any of them
}