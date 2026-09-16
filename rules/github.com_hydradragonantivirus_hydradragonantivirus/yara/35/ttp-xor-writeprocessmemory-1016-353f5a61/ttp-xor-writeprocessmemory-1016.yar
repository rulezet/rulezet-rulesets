rule TTP_XOR_WriteProcessMemory_1016 {
  strings:
    $key_1016 = { 47 64 [2] 75 46 [2] 73 73 [2] 5d 73 [2] 62 6f }

  condition:
    any of them
}