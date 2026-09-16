rule TTP_XOR_WriteProcessMemory_b49b {
  strings:
    $key_b49b = { e3 e9 [2] d1 cb [2] d7 fe [2] f9 fe [2] c6 e2 }

  condition:
    any of them
}