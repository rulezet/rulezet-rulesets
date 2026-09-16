rule TTP_XOR_WriteProcessMemory_a435 {
  strings:
    $key_a435 = { f3 47 [2] c1 65 [2] c7 50 [2] e9 50 [2] d6 4c }

  condition:
    any of them
}