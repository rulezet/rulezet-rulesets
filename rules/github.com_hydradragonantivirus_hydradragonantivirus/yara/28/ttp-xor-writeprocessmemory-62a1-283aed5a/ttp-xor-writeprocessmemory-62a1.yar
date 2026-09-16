rule TTP_XOR_WriteProcessMemory_62a1 {
  strings:
    $key_62a1 = { 35 d3 [2] 07 f1 [2] 01 c4 [2] 2f c4 [2] 10 d8 }

  condition:
    any of them
}