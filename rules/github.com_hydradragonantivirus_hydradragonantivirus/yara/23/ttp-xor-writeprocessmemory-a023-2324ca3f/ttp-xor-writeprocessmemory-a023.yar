rule TTP_XOR_WriteProcessMemory_a023 {
  strings:
    $key_a023 = { f7 51 [2] c5 73 [2] c3 46 [2] ed 46 [2] d2 5a }

  condition:
    any of them
}