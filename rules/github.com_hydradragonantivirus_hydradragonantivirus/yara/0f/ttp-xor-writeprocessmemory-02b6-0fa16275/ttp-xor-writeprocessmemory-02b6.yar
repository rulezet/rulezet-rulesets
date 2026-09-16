rule TTP_XOR_WriteProcessMemory_02b6 {
  strings:
    $key_02b6 = { 55 c4 [2] 67 e6 [2] 61 d3 [2] 4f d3 [2] 70 cf }

  condition:
    any of them
}