rule TTP_XOR_WriteProcessMemory_0a83 {
  strings:
    $key_0a83 = { 5d f1 [2] 6f d3 [2] 69 e6 [2] 47 e6 [2] 78 fa }

  condition:
    any of them
}