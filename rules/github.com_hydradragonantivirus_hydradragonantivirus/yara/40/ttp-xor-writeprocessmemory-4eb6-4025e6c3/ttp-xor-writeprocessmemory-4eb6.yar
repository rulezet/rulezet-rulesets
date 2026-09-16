rule TTP_XOR_WriteProcessMemory_4eb6 {
  strings:
    $key_4eb6 = { 19 c4 [2] 2b e6 [2] 2d d3 [2] 03 d3 [2] 3c cf }

  condition:
    any of them
}