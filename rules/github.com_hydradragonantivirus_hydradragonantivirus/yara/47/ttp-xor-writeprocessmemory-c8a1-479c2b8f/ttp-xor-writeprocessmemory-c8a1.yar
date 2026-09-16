rule TTP_XOR_WriteProcessMemory_c8a1 {
  strings:
    $key_c8a1 = { 9f d3 [2] ad f1 [2] ab c4 [2] 85 c4 [2] ba d8 }

  condition:
    any of them
}