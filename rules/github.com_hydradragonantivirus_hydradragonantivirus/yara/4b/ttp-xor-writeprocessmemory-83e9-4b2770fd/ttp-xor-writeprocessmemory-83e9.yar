rule TTP_XOR_WriteProcessMemory_83e9 {
  strings:
    $key_83e9 = { d4 9b [2] e6 b9 [2] e0 8c [2] ce 8c [2] f1 90 }

  condition:
    any of them
}