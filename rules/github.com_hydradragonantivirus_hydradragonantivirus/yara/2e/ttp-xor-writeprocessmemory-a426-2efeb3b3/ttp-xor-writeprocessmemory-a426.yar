rule TTP_XOR_WriteProcessMemory_a426 {
  strings:
    $key_a426 = { f3 54 [2] c1 76 [2] c7 43 [2] e9 43 [2] d6 5f }

  condition:
    any of them
}