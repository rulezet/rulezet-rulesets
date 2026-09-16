rule TTP_XOR_WriteProcessMemory_36b6 {
  strings:
    $key_36b6 = { 61 c4 [2] 53 e6 [2] 55 d3 [2] 7b d3 [2] 44 cf }

  condition:
    any of them
}