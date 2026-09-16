rule TTP_XOR_WriteProcessMemory_b79b {
  strings:
    $key_b79b = { e0 e9 [2] d2 cb [2] d4 fe [2] fa fe [2] c5 e2 }

  condition:
    any of them
}