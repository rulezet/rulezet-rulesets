rule TTP_XOR_WriteProcessMemory_25b6 {
  strings:
    $key_25b6 = { 72 c4 [2] 40 e6 [2] 46 d3 [2] 68 d3 [2] 57 cf }

  condition:
    any of them
}