rule TTP_XOR_WriteProcessMemory_0aa1 {
  strings:
    $key_0aa1 = { 5d d3 [2] 6f f1 [2] 69 c4 [2] 47 c4 [2] 78 d8 }

  condition:
    any of them
}