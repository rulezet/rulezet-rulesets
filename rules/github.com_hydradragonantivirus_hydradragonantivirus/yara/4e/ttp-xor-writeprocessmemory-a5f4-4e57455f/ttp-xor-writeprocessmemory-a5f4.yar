rule TTP_XOR_WriteProcessMemory_a5f4 {
  strings:
    $key_a5f4 = { f2 86 [2] c0 a4 [2] c6 91 [2] e8 91 [2] d7 8d }

  condition:
    any of them
}