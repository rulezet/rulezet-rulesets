rule TTP_XOR_WriteProcessMemory_8316 {
  strings:
    $key_8316 = { d4 64 [2] e6 46 [2] e0 73 [2] ce 73 [2] f1 6f }

  condition:
    any of them
}