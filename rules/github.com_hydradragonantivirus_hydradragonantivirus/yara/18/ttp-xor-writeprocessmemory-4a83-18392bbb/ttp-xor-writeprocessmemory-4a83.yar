rule TTP_XOR_WriteProcessMemory_4a83 {
  strings:
    $key_4a83 = { 1d f1 [2] 2f d3 [2] 29 e6 [2] 07 e6 [2] 38 fa }

  condition:
    any of them
}