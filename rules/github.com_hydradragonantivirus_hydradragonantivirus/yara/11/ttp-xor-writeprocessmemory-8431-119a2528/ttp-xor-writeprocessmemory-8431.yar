rule TTP_XOR_WriteProcessMemory_8431 {
  strings:
    $key_8431 = { d3 43 [2] e1 61 [2] e7 54 [2] c9 54 [2] f6 48 }

  condition:
    any of them
}