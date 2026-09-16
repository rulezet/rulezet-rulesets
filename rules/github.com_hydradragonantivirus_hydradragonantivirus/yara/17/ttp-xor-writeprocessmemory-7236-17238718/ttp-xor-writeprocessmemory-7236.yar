rule TTP_XOR_WriteProcessMemory_7236 {
  strings:
    $key_7236 = { 25 44 [2] 17 66 [2] 11 53 [2] 3f 53 [2] 00 4f }

  condition:
    any of them
}