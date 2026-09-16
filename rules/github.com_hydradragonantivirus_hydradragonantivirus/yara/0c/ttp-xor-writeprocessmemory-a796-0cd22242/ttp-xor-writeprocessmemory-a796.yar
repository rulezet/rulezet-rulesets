rule TTP_XOR_WriteProcessMemory_a796 {
  strings:
    $key_a796 = { f0 e4 [2] c2 c6 [2] c4 f3 [2] ea f3 [2] d5 ef }

  condition:
    any of them
}