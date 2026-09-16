rule TTP_XOR_WriteProcessMemory_85d3 {
  strings:
    $key_85d3 = { d2 a1 [2] e0 83 [2] e6 b6 [2] c8 b6 [2] f7 aa }

  condition:
    any of them
}