rule TTP_XOR_WriteProcessMemory_8434 {
  strings:
    $key_8434 = { d3 46 [2] e1 64 [2] e7 51 [2] c9 51 [2] f6 4d }

  condition:
    any of them
}