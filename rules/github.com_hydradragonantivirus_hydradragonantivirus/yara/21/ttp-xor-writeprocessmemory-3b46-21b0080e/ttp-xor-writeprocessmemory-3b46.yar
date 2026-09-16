rule TTP_XOR_WriteProcessMemory_3b46 {
  strings:
    $key_3b46 = { 6c 34 [2] 5e 16 [2] 58 23 [2] 76 23 [2] 49 3f }

  condition:
    any of them
}