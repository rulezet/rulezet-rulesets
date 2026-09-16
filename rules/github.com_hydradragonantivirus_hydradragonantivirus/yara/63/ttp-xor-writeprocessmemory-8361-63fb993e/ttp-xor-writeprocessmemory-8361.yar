rule TTP_XOR_WriteProcessMemory_8361 {
  strings:
    $key_8361 = { d4 13 [2] e6 31 [2] e0 04 [2] ce 04 [2] f1 18 }

  condition:
    any of them
}