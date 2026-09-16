rule TTP_XOR_WriteProcessMemory_8422 {
  strings:
    $key_8422 = { d3 50 [2] e1 72 [2] e7 47 [2] c9 47 [2] f6 5b }

  condition:
    any of them
}