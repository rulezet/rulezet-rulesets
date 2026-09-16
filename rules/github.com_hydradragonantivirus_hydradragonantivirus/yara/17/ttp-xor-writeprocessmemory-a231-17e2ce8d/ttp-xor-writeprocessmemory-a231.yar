rule TTP_XOR_WriteProcessMemory_a231 {
  strings:
    $key_a231 = { f5 43 [2] c7 61 [2] c1 54 [2] ef 54 [2] d0 48 }

  condition:
    any of them
}