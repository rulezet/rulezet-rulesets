rule TTP_XOR_WriteProcessMemory_5eb2 {
  strings:
    $key_5eb2 = { 09 c0 [2] 3b e2 [2] 3d d7 [2] 13 d7 [2] 2c cb }

  condition:
    any of them
}