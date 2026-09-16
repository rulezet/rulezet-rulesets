rule TTP_XOR_WriteProcessMemory_8359 {
  strings:
    $key_8359 = { d4 2b [2] e6 09 [2] e0 3c [2] ce 3c [2] f1 20 }

  condition:
    any of them
}