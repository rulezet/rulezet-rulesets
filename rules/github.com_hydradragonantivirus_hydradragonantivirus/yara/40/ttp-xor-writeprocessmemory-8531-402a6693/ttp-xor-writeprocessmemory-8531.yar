rule TTP_XOR_WriteProcessMemory_8531 {
  strings:
    $key_8531 = { d2 43 [2] e0 61 [2] e6 54 [2] c8 54 [2] f7 48 }

  condition:
    any of them
}