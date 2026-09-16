rule TTP_XOR_WriteProcessMemory_a522 {
  strings:
    $key_a522 = { f2 50 [2] c0 72 [2] c6 47 [2] e8 47 [2] d7 5b }

  condition:
    any of them
}