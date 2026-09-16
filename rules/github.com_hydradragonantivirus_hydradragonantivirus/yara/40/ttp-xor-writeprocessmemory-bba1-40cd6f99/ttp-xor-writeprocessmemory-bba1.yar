rule TTP_XOR_WriteProcessMemory_bba1 {
  strings:
    $key_bba1 = { ec d3 [2] de f1 [2] d8 c4 [2] f6 c4 [2] c9 d8 }

  condition:
    any of them
}