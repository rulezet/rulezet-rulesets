rule TTP_XOR_WriteProcessMemory_8306 {
  strings:
    $key_8306 = { d4 74 [2] e6 56 [2] e0 63 [2] ce 63 [2] f1 7f }

  condition:
    any of them
}