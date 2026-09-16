rule TTP_XOR_WriteProcessMemory_2eb6 {
  strings:
    $key_2eb6 = { 79 c4 [2] 4b e6 [2] 4d d3 [2] 63 d3 [2] 5c cf }

  condition:
    any of them
}