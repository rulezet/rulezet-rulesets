rule TTP_XOR_WriteProcessMemory_1b46 {
  strings:
    $key_1b46 = { 4c 34 [2] 7e 16 [2] 78 23 [2] 56 23 [2] 69 3f }

  condition:
    any of them
}