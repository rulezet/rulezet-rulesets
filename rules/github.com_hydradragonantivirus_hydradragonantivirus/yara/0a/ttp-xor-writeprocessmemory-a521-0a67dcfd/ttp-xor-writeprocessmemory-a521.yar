rule TTP_XOR_WriteProcessMemory_a521 {
  strings:
    $key_a521 = { f2 53 [2] c0 71 [2] c6 44 [2] e8 44 [2] d7 58 }

  condition:
    any of them
}