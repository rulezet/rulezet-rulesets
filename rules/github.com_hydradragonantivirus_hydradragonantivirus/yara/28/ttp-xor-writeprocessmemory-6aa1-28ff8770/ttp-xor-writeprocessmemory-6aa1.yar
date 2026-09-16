rule TTP_XOR_WriteProcessMemory_6aa1 {
  strings:
    $key_6aa1 = { 3d d3 [2] 0f f1 [2] 09 c4 [2] 27 c4 [2] 18 d8 }

  condition:
    any of them
}