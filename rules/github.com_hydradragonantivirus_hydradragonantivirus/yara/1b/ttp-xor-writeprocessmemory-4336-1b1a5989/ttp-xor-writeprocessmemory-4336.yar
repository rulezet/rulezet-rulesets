rule TTP_XOR_WriteProcessMemory_4336 {
  strings:
    $key_4336 = { 14 44 [2] 26 66 [2] 20 53 [2] 0e 53 [2] 31 4f }

  condition:
    any of them
}