rule TTP_XOR_WriteProcessMemory_c9b6 {
  strings:
    $key_c9b6 = { 9e c4 [2] ac e6 [2] aa d3 [2] 84 d3 [2] bb cf }

  condition:
    any of them
}