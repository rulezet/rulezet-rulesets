rule TTP_XOR_WriteProcessMemory_a423 {
  strings:
    $key_a423 = { f3 51 [2] c1 73 [2] c7 46 [2] e9 46 [2] d6 5a }

  condition:
    any of them
}