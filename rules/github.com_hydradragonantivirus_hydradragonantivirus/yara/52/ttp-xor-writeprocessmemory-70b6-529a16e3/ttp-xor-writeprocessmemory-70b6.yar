rule TTP_XOR_WriteProcessMemory_70b6 {
  strings:
    $key_70b6 = { 27 c4 [2] 15 e6 [2] 13 d3 [2] 3d d3 [2] 02 cf }

  condition:
    any of them
}