rule TTP_XOR_WriteProcessMemory_96d3 {
  strings:
    $key_96d3 = { c1 a1 [2] f3 83 [2] f5 b6 [2] db b6 [2] e4 aa }

  condition:
    any of them
}