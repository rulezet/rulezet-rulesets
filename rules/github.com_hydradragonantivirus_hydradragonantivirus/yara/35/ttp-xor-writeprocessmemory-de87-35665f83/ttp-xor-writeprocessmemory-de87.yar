rule TTP_XOR_WriteProcessMemory_de87 {
  strings:
    $key_de87 = { 89 f5 [2] bb d7 [2] bd e2 [2] 93 e2 [2] ac fe }

  condition:
    any of them
}