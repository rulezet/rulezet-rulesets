rule TTP_XOR_WriteProcessMemory_64b6 {
  strings:
    $key_64b6 = { 33 c4 [2] 01 e6 [2] 07 d3 [2] 29 d3 [2] 16 cf }

  condition:
    any of them
}