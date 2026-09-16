rule TTP_XOR_WriteProcessMemory_8444 {
  strings:
    $key_8444 = { d3 36 [2] e1 14 [2] e7 21 [2] c9 21 [2] f6 3d }

  condition:
    any of them
}