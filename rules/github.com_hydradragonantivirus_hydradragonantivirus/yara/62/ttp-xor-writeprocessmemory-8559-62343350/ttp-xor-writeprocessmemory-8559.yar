rule TTP_XOR_WriteProcessMemory_8559 {
  strings:
    $key_8559 = { d2 2b [2] e0 09 [2] e6 3c [2] c8 3c [2] f7 20 }

  condition:
    any of them
}