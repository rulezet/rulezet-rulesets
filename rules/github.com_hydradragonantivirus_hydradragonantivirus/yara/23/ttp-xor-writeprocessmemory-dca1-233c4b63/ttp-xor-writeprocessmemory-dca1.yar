rule TTP_XOR_WriteProcessMemory_dca1 {
  strings:
    $key_dca1 = { 8b d3 [2] b9 f1 [2] bf c4 [2] 91 c4 [2] ae d8 }

  condition:
    any of them
}