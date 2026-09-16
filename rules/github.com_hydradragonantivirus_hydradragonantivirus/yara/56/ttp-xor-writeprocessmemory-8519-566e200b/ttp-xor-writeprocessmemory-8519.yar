rule TTP_XOR_WriteProcessMemory_8519 {
  strings:
    $key_8519 = { d2 6b [2] e0 49 [2] e6 7c [2] c8 7c [2] f7 60 }

  condition:
    any of them
}