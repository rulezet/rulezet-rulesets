rule TTP_XOR_WriteProcessMemory_a286 {
  strings:
    $key_a286 = { f5 f4 [2] c7 d6 [2] c1 e3 [2] ef e3 [2] d0 ff }

  condition:
    any of them
}