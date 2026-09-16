rule TTP_XOR_WriteProcessMemory_4716 {
  strings:
    $key_4716 = { 10 64 [2] 22 46 [2] 24 73 [2] 0a 73 [2] 35 6f }

  condition:
    any of them
}