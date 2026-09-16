rule TTP_XOR_WriteProcessMemory_7a83 {
  strings:
    $key_7a83 = { 2d f1 [2] 1f d3 [2] 19 e6 [2] 37 e6 [2] 08 fa }

  condition:
    any of them
}