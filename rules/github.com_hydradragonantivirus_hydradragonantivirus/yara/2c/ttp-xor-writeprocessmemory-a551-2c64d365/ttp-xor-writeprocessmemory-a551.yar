rule TTP_XOR_WriteProcessMemory_a551 {
  strings:
    $key_a551 = { f2 23 [2] c0 01 [2] c6 34 [2] e8 34 [2] d7 28 }

  condition:
    any of them
}