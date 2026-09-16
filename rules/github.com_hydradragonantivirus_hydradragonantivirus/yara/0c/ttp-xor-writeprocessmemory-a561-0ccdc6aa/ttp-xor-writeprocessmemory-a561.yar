rule TTP_XOR_WriteProcessMemory_a561 {
  strings:
    $key_a561 = { f2 13 [2] c0 31 [2] c6 04 [2] e8 04 [2] d7 18 }

  condition:
    any of them
}