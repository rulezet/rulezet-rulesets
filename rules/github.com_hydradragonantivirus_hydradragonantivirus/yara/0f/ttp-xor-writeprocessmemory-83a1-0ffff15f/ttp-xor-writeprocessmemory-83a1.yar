rule TTP_XOR_WriteProcessMemory_83a1 {
  strings:
    $key_83a1 = { d4 d3 [2] e6 f1 [2] e0 c4 [2] ce c4 [2] f1 d8 }

  condition:
    any of them
}