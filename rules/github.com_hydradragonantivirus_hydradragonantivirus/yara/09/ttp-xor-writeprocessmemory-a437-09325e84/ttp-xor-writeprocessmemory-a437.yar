rule TTP_XOR_WriteProcessMemory_a437 {
  strings:
    $key_a437 = { f3 45 [2] c1 67 [2] c7 52 [2] e9 52 [2] d6 4e }

  condition:
    any of them
}