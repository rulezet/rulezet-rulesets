rule TTP_XOR_WriteProcessMemory_0eb6 {
  strings:
    $key_0eb6 = { 59 c4 [2] 6b e6 [2] 6d d3 [2] 43 d3 [2] 7c cf }

  condition:
    any of them
}