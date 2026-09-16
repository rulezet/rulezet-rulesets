rule TTP_XOR_WriteProcessMemory_8447 {
  strings:
    $key_8447 = { d3 35 [2] e1 17 [2] e7 22 [2] c9 22 [2] f6 3e }

  condition:
    any of them
}