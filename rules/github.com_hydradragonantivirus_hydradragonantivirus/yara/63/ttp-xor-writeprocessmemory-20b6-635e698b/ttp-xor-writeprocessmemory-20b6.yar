rule TTP_XOR_WriteProcessMemory_20b6 {
  strings:
    $key_20b6 = { 77 c4 [2] 45 e6 [2] 43 d3 [2] 6d d3 [2] 52 cf }

  condition:
    any of them
}