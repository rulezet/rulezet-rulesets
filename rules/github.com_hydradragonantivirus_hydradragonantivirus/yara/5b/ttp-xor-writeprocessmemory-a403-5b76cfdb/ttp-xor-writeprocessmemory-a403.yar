rule TTP_XOR_WriteProcessMemory_a403 {
  strings:
    $key_a403 = { f3 71 [2] c1 53 [2] c7 66 [2] e9 66 [2] d6 7a }

  condition:
    any of them
}