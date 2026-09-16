rule TTP_XOR_WriteProcessMemory_8340 {
  strings:
    $key_8340 = { d4 32 [2] e6 10 [2] e0 25 [2] ce 25 [2] f1 39 }

  condition:
    any of them
}