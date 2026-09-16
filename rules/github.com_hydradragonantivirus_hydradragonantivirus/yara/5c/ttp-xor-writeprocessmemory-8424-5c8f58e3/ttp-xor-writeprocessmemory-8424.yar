rule TTP_XOR_WriteProcessMemory_8424 {
  strings:
    $key_8424 = { d3 56 [2] e1 74 [2] e7 41 [2] c9 41 [2] f6 5d }

  condition:
    any of them
}