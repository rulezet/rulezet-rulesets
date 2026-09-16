rule TTP_XOR_WriteProcessMemory_a474 {
  strings:
    $key_a474 = { f3 06 [2] c1 24 [2] c7 11 [2] e9 11 [2] d6 0d }

  condition:
    any of them
}