rule TTP_XOR_WriteProcessMemory_8320 {
  strings:
    $key_8320 = { d4 52 [2] e6 70 [2] e0 45 [2] ce 45 [2] f1 59 }

  condition:
    any of them
}