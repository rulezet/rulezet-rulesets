rule TTP_XOR_WriteProcessMemory_8309 {
  strings:
    $key_8309 = { d4 7b [2] e6 59 [2] e0 6c [2] ce 6c [2] f1 70 }

  condition:
    any of them
}