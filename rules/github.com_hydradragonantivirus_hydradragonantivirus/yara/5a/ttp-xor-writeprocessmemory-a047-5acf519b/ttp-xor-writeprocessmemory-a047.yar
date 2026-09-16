rule TTP_XOR_WriteProcessMemory_a047 {
  strings:
    $key_a047 = { f7 35 [2] c5 17 [2] c3 22 [2] ed 22 [2] d2 3e }

  condition:
    any of them
}