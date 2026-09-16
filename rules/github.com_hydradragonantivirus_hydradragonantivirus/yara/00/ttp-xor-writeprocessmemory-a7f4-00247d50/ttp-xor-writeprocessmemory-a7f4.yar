rule TTP_XOR_WriteProcessMemory_a7f4 {
  strings:
    $key_a7f4 = { f0 86 [2] c2 a4 [2] c4 91 [2] ea 91 [2] d5 8d }

  condition:
    any of them
}