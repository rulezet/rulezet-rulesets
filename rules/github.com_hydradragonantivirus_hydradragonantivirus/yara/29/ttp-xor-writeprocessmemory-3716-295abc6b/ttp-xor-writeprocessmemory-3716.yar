rule TTP_XOR_WriteProcessMemory_3716 {
  strings:
    $key_3716 = { 60 64 [2] 52 46 [2] 54 73 [2] 7a 73 [2] 45 6f }

  condition:
    any of them
}