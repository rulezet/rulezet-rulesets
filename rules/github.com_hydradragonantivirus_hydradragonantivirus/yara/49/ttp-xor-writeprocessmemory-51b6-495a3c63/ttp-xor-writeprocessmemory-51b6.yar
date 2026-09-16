rule TTP_XOR_WriteProcessMemory_51b6 {
  strings:
    $key_51b6 = { 06 c4 [2] 34 e6 [2] 32 d3 [2] 1c d3 [2] 23 cf }

  condition:
    any of them
}