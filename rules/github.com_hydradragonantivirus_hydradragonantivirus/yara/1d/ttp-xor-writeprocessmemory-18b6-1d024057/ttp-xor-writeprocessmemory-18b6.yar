rule TTP_XOR_WriteProcessMemory_18b6 {
  strings:
    $key_18b6 = { 4f c4 [2] 7d e6 [2] 7b d3 [2] 55 d3 [2] 6a cf }

  condition:
    any of them
}