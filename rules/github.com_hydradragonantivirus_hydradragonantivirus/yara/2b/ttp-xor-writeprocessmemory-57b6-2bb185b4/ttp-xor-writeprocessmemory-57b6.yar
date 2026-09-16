rule TTP_XOR_WriteProcessMemory_57b6 {
  strings:
    $key_57b6 = { 00 c4 [2] 32 e6 [2] 34 d3 [2] 1a d3 [2] 25 cf }

  condition:
    any of them
}