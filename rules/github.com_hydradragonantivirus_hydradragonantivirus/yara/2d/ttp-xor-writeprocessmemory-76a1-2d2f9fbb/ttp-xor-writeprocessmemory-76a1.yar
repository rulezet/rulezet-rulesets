rule TTP_XOR_WriteProcessMemory_76a1 {
  strings:
    $key_76a1 = { 21 d3 [2] 13 f1 [2] 15 c4 [2] 3b c4 [2] 04 d8 }

  condition:
    any of them
}