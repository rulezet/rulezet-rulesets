rule TTP_XOR_WriteProcessMemory_eeb6 {
  strings:
    $key_eeb6 = { b9 c4 [2] 8b e6 [2] 8d d3 [2] a3 d3 [2] 9c cf }

  condition:
    any of them
}