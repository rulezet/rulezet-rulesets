rule TTP_XOR_WriteProcessMemory_3a83 {
  strings:
    $key_3a83 = { 6d f1 [2] 5f d3 [2] 59 e6 [2] 77 e6 [2] 48 fa }

  condition:
    any of them
}