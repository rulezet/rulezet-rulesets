rule TTP_XOR_WriteProcessMemory_a447 {
  strings:
    $key_a447 = { f3 35 [2] c1 17 [2] c7 22 [2] e9 22 [2] d6 3e }

  condition:
    any of them
}