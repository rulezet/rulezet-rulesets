rule TTP_XOR_WriteProcessMemory_52b6 {
  strings:
    $key_52b6 = { 05 c4 [2] 37 e6 [2] 31 d3 [2] 1f d3 [2] 20 cf }

  condition:
    any of them
}