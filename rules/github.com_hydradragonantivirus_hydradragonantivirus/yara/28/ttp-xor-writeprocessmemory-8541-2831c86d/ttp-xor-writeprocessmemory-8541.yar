rule TTP_XOR_WriteProcessMemory_8541 {
  strings:
    $key_8541 = { d2 33 [2] e0 11 [2] e6 24 [2] c8 24 [2] f7 38 }

  condition:
    any of them
}