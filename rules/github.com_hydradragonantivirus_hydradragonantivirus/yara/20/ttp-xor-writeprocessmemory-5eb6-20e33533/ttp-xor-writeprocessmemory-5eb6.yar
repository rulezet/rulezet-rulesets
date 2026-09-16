rule TTP_XOR_WriteProcessMemory_5eb6 {
  strings:
    $key_5eb6 = { 09 c4 [2] 3b e6 [2] 3d d3 [2] 13 d3 [2] 2c cf }

  condition:
    any of them
}