rule TTP_XOR_WriteProcessMemory_83e0 {
  strings:
    $key_83e0 = { d4 92 [2] e6 b0 [2] e0 85 [2] ce 85 [2] f1 99 }

  condition:
    any of them
}