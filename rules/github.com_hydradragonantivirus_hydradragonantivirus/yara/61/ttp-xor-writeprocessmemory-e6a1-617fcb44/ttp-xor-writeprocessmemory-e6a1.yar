rule TTP_XOR_WriteProcessMemory_e6a1 {
  strings:
    $key_e6a1 = { b1 d3 [2] 83 f1 [2] 85 c4 [2] ab c4 [2] 94 d8 }

  condition:
    any of them
}