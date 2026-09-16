rule TTP_XOR_WriteProcessMemory_a49b {
  strings:
    $key_a49b = { f3 e9 [2] c1 cb [2] c7 fe [2] e9 fe [2] d6 e2 }

  condition:
    any of them
}