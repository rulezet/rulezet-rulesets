rule TTP_XOR_WriteProcessMemory_de97 {
  strings:
    $key_de97 = { 89 e5 [2] bb c7 [2] bd f2 [2] 93 f2 [2] ac ee }

  condition:
    any of them
}