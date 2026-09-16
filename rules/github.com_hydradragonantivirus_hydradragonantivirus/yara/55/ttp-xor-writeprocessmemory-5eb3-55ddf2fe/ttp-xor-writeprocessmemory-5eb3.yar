rule TTP_XOR_WriteProcessMemory_5eb3 {
  strings:
    $key_5eb3 = { 09 c1 [2] 3b e3 [2] 3d d6 [2] 13 d6 [2] 2c ca }

  condition:
    any of them
}