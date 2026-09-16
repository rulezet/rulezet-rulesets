rule TTP_XOR_WriteProcessMemory_a793 {
  strings:
    $key_a793 = { f0 e1 [2] c2 c3 [2] c4 f6 [2] ea f6 [2] d5 ea }

  condition:
    any of them
}