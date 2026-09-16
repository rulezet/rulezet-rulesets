rule TTP_XOR_WriteProcessMemory_8322 {
  strings:
    $key_8322 = { d4 50 [2] e6 72 [2] e0 47 [2] ce 47 [2] f1 5b }

  condition:
    any of them
}