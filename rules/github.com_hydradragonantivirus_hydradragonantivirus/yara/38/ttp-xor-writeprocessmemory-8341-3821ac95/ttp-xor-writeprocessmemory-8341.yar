rule TTP_XOR_WriteProcessMemory_8341 {
  strings:
    $key_8341 = { d4 33 [2] e6 11 [2] e0 24 [2] ce 24 [2] f1 38 }

  condition:
    any of them
}