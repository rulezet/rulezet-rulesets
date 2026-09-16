rule TTP_XOR_WriteProcessMemory_8364 {
  strings:
    $key_8364 = { d4 16 [2] e6 34 [2] e0 01 [2] ce 01 [2] f1 1d }

  condition:
    any of them
}