rule TTP_XOR_WriteProcessMemory_8357 {
  strings:
    $key_8357 = { d4 25 [2] e6 07 [2] e0 32 [2] ce 32 [2] f1 2e }

  condition:
    any of them
}