rule TTP_XOR_WriteProcessMemory_3336 {
  strings:
    $key_3336 = { 64 44 [2] 56 66 [2] 50 53 [2] 7e 53 [2] 41 4f }

  condition:
    any of them
}