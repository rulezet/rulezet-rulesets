rule TTP_XOR_WriteProcessMemory_7aa1 {
  strings:
    $key_7aa1 = { 2d d3 [2] 1f f1 [2] 19 c4 [2] 37 c4 [2] 08 d8 }

  condition:
    any of them
}