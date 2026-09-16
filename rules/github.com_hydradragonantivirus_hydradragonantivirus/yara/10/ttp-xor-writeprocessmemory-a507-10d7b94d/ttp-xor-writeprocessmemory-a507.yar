rule TTP_XOR_WriteProcessMemory_a507 {
  strings:
    $key_a507 = { f2 75 [2] c0 57 [2] c6 62 [2] e8 62 [2] d7 7e }

  condition:
    any of them
}