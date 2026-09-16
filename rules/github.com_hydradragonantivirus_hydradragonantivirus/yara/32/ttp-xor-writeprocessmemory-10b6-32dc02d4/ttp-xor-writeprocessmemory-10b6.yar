rule TTP_XOR_WriteProcessMemory_10b6 {
  strings:
    $key_10b6 = { 47 c4 [2] 75 e6 [2] 73 d3 [2] 5d d3 [2] 62 cf }

  condition:
    any of them
}