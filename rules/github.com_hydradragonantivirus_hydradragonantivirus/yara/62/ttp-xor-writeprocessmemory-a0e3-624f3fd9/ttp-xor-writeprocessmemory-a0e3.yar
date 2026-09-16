rule TTP_XOR_WriteProcessMemory_a0e3 {
  strings:
    $key_a0e3 = { f7 91 [2] c5 b3 [2] c3 86 [2] ed 86 [2] d2 9a }

  condition:
    any of them
}