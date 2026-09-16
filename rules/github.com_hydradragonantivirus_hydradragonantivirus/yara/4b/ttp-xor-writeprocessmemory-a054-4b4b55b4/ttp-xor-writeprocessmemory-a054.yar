rule TTP_XOR_WriteProcessMemory_a054 {
  strings:
    $key_a054 = { f7 26 [2] c5 04 [2] c3 31 [2] ed 31 [2] d2 2d }

  condition:
    any of them
}