rule TTP_XOR_WriteProcessMemory_8509 {
  strings:
    $key_8509 = { d2 7b [2] e0 59 [2] e6 6c [2] c8 6c [2] f7 70 }

  condition:
    any of them
}