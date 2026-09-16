rule TTP_XOR_WriteProcessMemory_a445 {
  strings:
    $key_a445 = { f3 37 [2] c1 15 [2] c7 20 [2] e9 20 [2] d6 3c }

  condition:
    any of them
}