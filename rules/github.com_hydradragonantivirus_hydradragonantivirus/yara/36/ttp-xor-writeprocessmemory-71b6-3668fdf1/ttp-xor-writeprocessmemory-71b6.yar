rule TTP_XOR_WriteProcessMemory_71b6 {
  strings:
    $key_71b6 = { 26 c4 [2] 14 e6 [2] 12 d3 [2] 3c d3 [2] 03 cf }

  condition:
    any of them
}