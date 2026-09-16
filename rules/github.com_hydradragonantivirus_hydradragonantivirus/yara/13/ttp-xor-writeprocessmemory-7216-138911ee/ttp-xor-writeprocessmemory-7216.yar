rule TTP_XOR_WriteProcessMemory_7216 {
  strings:
    $key_7216 = { 25 64 [2] 17 46 [2] 11 73 [2] 3f 73 [2] 00 6f }

  condition:
    any of them
}