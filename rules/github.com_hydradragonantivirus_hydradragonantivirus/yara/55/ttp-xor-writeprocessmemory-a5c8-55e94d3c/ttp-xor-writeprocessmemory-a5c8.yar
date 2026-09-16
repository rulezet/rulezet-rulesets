rule TTP_XOR_WriteProcessMemory_a5c8 {
  strings:
    $key_a5c8 = { f2 ba [2] c0 98 [2] c6 ad [2] e8 ad [2] d7 b1 }

  condition:
    any of them
}