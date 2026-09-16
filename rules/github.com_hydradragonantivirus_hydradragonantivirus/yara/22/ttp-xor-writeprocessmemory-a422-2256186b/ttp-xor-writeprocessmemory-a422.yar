rule TTP_XOR_WriteProcessMemory_a422 {
  strings:
    $key_a422 = { f3 50 [2] c1 72 [2] c7 47 [2] e9 47 [2] d6 5b }

  condition:
    any of them
}