rule TTP_XOR_WriteProcessMemory_2463 {
  strings:
    $key_2463 = { 73 11 [2] 41 33 [2] 47 06 [2] 69 06 [2] 56 1a }

  condition:
    any of them
}