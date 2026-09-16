rule TTP_XOR_WriteProcessMemory_a218 {
  strings:
    $key_a218 = { f5 6a [2] c7 48 [2] c1 7d [2] ef 7d [2] d0 61 }

  condition:
    any of them
}