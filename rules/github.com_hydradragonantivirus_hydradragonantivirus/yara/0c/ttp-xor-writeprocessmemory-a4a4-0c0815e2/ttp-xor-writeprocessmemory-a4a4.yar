rule TTP_XOR_WriteProcessMemory_a4a4 {
  strings:
    $key_a4a4 = { f3 d6 [2] c1 f4 [2] c7 c1 [2] e9 c1 [2] d6 dd }

  condition:
    any of them
}