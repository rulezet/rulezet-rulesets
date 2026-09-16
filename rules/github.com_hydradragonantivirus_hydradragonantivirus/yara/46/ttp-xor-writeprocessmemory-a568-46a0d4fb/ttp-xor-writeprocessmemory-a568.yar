rule TTP_XOR_WriteProcessMemory_a568 {
  strings:
    $key_a568 = { f2 1a [2] c0 38 [2] c6 0d [2] e8 0d [2] d7 11 }

  condition:
    any of them
}