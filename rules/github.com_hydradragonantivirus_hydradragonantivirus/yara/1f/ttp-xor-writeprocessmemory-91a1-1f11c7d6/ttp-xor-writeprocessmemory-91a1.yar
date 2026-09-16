rule TTP_XOR_WriteProcessMemory_91a1 {
  strings:
    $key_91a1 = { c6 d3 [2] f4 f1 [2] f2 c4 [2] dc c4 [2] e3 d8 }

  condition:
    any of them
}