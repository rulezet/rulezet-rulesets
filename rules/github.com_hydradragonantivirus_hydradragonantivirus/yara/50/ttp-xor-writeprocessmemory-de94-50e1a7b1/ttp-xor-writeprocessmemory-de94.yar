rule TTP_XOR_WriteProcessMemory_de94 {
  strings:
    $key_de94 = { 89 e6 [2] bb c4 [2] bd f1 [2] 93 f1 [2] ac ed }

  condition:
    any of them
}