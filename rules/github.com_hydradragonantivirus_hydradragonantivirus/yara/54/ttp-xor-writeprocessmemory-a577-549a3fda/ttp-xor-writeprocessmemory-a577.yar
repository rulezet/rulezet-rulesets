rule TTP_XOR_WriteProcessMemory_a577 {
  strings:
    $key_a577 = { f2 05 [2] c0 27 [2] c6 12 [2] e8 12 [2] d7 0e }

  condition:
    any of them
}