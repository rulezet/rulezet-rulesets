rule TTP_XOR_WriteProcessMemory_a454 {
  strings:
    $key_a454 = { f3 26 [2] c1 04 [2] c7 31 [2] e9 31 [2] d6 2d }

  condition:
    any of them
}