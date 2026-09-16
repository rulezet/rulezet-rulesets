rule TTP_XOR_WriteProcessMemory_8216 {
  strings:
    $key_8216 = { d5 64 [2] e7 46 [2] e1 73 [2] cf 73 [2] f0 6f }

  condition:
    any of them
}