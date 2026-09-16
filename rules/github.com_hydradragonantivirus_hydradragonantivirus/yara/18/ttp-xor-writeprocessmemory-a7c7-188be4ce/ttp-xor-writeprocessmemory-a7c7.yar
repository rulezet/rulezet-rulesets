rule TTP_XOR_WriteProcessMemory_a7c7 {
  strings:
    $key_a7c7 = { f0 b5 [2] c2 97 [2] c4 a2 [2] ea a2 [2] d5 be }

  condition:
    any of them
}