rule TTP_XOR_WriteProcessMemory_a5e3 {
  strings:
    $key_a5e3 = { f2 91 [2] c0 b3 [2] c6 86 [2] e8 86 [2] d7 9a }

  condition:
    any of them
}