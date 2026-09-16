rule TTP_XOR_WriteProcessMemory_efa1 {
  strings:
    $key_efa1 = { b8 d3 [2] 8a f1 [2] 8c c4 [2] a2 c4 [2] 9d d8 }

  condition:
    any of them
}