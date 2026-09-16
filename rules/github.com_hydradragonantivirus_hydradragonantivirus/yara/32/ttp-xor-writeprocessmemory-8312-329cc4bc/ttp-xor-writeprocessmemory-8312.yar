rule TTP_XOR_WriteProcessMemory_8312 {
  strings:
    $key_8312 = { d4 60 [2] e6 42 [2] e0 77 [2] ce 77 [2] f1 6b }

  condition:
    any of them
}