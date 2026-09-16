rule TTP_XOR_WriteProcessMemory_a7d7 {
  strings:
    $key_a7d7 = { f0 a5 [2] c2 87 [2] c4 b2 [2] ea b2 [2] d5 ae }

  condition:
    any of them
}