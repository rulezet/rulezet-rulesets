rule TTP_XOR_WriteProcessMemory_4ab6 {
  strings:
    $key_4ab6 = { 1d c4 [2] 2f e6 [2] 29 d3 [2] 07 d3 [2] 38 cf }

  condition:
    any of them
}