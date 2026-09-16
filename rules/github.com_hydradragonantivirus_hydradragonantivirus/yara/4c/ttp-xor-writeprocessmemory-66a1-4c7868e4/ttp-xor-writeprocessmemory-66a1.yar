rule TTP_XOR_WriteProcessMemory_66a1 {
  strings:
    $key_66a1 = { 31 d3 [2] 03 f1 [2] 05 c4 [2] 2b c4 [2] 14 d8 }

  condition:
    any of them
}