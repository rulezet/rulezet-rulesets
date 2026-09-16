rule TTP_XOR_WriteProcessMemory_a283 {
  strings:
    $key_a283 = { f5 f1 [2] c7 d3 [2] c1 e6 [2] ef e6 [2] d0 fa }

  condition:
    any of them
}