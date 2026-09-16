rule TTP_XOR_WriteProcessMemory_8321 {
  strings:
    $key_8321 = { d4 53 [2] e6 71 [2] e0 44 [2] ce 44 [2] f1 58 }

  condition:
    any of them
}