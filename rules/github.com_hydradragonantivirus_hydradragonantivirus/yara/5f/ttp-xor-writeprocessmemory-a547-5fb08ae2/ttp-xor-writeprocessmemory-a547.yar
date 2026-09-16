rule TTP_XOR_WriteProcessMemory_a547 {
  strings:
    $key_a547 = { f2 35 [2] c0 17 [2] c6 22 [2] e8 22 [2] d7 3e }

  condition:
    any of them
}