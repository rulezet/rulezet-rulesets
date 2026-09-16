rule TTP_XOR_WriteProcessMemory_12b6 {
  strings:
    $key_12b6 = { 45 c4 [2] 77 e6 [2] 71 d3 [2] 5f d3 [2] 60 cf }

  condition:
    any of them
}