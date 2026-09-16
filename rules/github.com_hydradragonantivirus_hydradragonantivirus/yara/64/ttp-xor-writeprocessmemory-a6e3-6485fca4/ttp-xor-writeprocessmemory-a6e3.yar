rule TTP_XOR_WriteProcessMemory_a6e3 {
  strings:
    $key_a6e3 = { f1 91 [2] c3 b3 [2] c5 86 [2] eb 86 [2] d4 9a }

  condition:
    any of them
}