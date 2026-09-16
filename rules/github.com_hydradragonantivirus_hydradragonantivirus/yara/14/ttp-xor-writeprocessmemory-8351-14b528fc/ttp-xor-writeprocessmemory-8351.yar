rule TTP_XOR_WriteProcessMemory_8351 {
  strings:
    $key_8351 = { d4 23 [2] e6 01 [2] e0 34 [2] ce 34 [2] f1 28 }

  condition:
    any of them
}