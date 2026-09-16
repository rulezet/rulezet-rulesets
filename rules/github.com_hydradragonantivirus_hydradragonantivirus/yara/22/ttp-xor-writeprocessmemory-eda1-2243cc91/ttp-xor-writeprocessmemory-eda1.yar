rule TTP_XOR_WriteProcessMemory_eda1 {
  strings:
    $key_eda1 = { ba d3 [2] 88 f1 [2] 8e c4 [2] a0 c4 [2] 9f d8 }

  condition:
    any of them
}