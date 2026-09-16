rule TTP_XOR_WriteProcessMemory_a3c8 {
  strings:
    $key_a3c8 = { f4 ba [2] c6 98 [2] c0 ad [2] ee ad [2] d1 b1 }

  condition:
    any of them
}