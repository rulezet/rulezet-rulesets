rule TTP_XOR_WriteProcessMemory_33b6 {
  strings:
    $key_33b6 = { 64 c4 [2] 56 e6 [2] 50 d3 [2] 7e d3 [2] 41 cf }

  condition:
    any of them
}