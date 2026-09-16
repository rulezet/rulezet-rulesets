rule TTP_XOR_WriteProcessMemory_a442 {
  strings:
    $key_a442 = { f3 30 [2] c1 12 [2] c7 27 [2] e9 27 [2] d6 3b }

  condition:
    any of them
}