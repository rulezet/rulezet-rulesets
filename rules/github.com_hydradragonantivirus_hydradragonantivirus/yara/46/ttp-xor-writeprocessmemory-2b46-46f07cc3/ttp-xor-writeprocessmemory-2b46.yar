rule TTP_XOR_WriteProcessMemory_2b46 {
  strings:
    $key_2b46 = { 7c 34 [2] 4e 16 [2] 48 23 [2] 66 23 [2] 59 3f }

  condition:
    any of them
}