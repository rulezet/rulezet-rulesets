rule TTP_XOR_WriteProcessMemory_b78c {
  strings:
    $key_b78c = { e0 fe [2] d2 dc [2] d4 e9 [2] fa e9 [2] c5 f5 }

  condition:
    any of them
}