rule TTP_XOR_WriteProcessMemory_5a83 {
  strings:
    $key_5a83 = { 0d f1 [2] 3f d3 [2] 39 e6 [2] 17 e6 [2] 28 fa }

  condition:
    any of them
}