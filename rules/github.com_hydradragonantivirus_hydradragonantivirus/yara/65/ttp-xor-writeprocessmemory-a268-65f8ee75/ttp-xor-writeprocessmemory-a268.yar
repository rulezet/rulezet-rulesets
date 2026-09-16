rule TTP_XOR_WriteProcessMemory_a268 {
  strings:
    $key_a268 = { f5 1a [2] c7 38 [2] c1 0d [2] ef 0d [2] d0 11 }

  condition:
    any of them
}