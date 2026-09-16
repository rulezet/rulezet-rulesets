rule TTP_XOR_WriteProcessMemory_a460 {
  strings:
    $key_a460 = { f3 12 [2] c1 30 [2] c7 05 [2] e9 05 [2] d6 19 }

  condition:
    any of them
}