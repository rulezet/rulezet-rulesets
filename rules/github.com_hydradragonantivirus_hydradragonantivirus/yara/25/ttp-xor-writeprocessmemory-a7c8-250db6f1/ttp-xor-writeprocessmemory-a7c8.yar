rule TTP_XOR_WriteProcessMemory_a7c8 {
  strings:
    $key_a7c8 = { f0 ba [2] c2 98 [2] c4 ad [2] ea ad [2] d5 b1 }

  condition:
    any of them
}