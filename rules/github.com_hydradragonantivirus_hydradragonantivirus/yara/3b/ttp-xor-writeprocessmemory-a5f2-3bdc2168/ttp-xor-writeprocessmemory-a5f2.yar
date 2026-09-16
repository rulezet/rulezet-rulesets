rule TTP_XOR_WriteProcessMemory_a5f2 {
  strings:
    $key_a5f2 = { f2 80 [2] c0 a2 [2] c6 97 [2] e8 97 [2] d7 8b }

  condition:
    any of them
}