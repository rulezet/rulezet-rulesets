rule TTP_XOR_WriteProcessMemory_8480 {
  strings:
    $key_8480 = { d3 f2 [2] e1 d0 [2] e7 e5 [2] c9 e5 [2] f6 f9 }

  condition:
    any of them
}