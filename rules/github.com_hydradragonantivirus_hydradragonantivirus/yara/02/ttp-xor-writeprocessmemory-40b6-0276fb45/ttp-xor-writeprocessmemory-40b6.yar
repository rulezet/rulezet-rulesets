rule TTP_XOR_WriteProcessMemory_40b6 {
  strings:
    $key_40b6 = { 17 c4 [2] 25 e6 [2] 23 d3 [2] 0d d3 [2] 32 cf }

  condition:
    any of them
}