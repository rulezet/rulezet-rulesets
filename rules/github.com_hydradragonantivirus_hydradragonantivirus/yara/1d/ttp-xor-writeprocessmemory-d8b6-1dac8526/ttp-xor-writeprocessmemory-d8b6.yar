rule TTP_XOR_WriteProcessMemory_d8b6 {
  strings:
    $key_d8b6 = { 8f c4 [2] bd e6 [2] bb d3 [2] 95 d3 [2] aa cf }

  condition:
    any of them
}