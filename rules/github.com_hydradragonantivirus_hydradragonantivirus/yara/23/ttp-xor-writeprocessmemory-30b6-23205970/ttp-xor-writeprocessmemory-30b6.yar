rule TTP_XOR_WriteProcessMemory_30b6 {
  strings:
    $key_30b6 = { 67 c4 [2] 55 e6 [2] 53 d3 [2] 7d d3 [2] 42 cf }

  condition:
    any of them
}