rule TTP_XOR_WriteProcessMemory_8411 {
  strings:
    $key_8411 = { d3 63 [2] e1 41 [2] e7 74 [2] c9 74 [2] f6 68 }

  condition:
    any of them
}