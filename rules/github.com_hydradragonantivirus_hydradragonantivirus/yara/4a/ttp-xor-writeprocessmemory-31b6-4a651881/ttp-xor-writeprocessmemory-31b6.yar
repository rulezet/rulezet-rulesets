rule TTP_XOR_WriteProcessMemory_31b6 {
  strings:
    $key_31b6 = { 66 c4 [2] 54 e6 [2] 52 d3 [2] 7c d3 [2] 43 cf }

  condition:
    any of them
}