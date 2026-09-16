rule TTP_XOR_WriteProcessMemory_8300 {
  strings:
    $key_8300 = { d4 72 [2] e6 50 [2] e0 65 [2] ce 65 [2] f1 79 }

  condition:
    any of them
}