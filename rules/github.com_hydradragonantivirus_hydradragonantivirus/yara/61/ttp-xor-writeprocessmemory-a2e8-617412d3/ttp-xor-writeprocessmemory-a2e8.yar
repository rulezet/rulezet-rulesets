rule TTP_XOR_WriteProcessMemory_a2e8 {
  strings:
    $key_a2e8 = { f5 9a [2] c7 b8 [2] c1 8d [2] ef 8d [2] d0 91 }

  condition:
    any of them
}