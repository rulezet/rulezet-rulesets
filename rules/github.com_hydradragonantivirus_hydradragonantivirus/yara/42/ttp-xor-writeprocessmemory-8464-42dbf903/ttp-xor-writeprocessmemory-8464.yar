rule TTP_XOR_WriteProcessMemory_8464 {
  strings:
    $key_8464 = { d3 16 [2] e1 34 [2] e7 01 [2] c9 01 [2] f6 1d }

  condition:
    any of them
}