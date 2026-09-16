rule TTP_XOR_WriteProcessMemory_2772 {
  strings:
    $key_2772 = { 70 00 [2] 42 22 [2] 44 17 [2] 6a 17 [2] 55 0b }

  condition:
    any of them
}