rule TTP_XOR_WriteProcessMemory_b19b {
  strings:
    $key_b19b = { e6 e9 [2] d4 cb [2] d2 fe [2] fc fe [2] c3 e2 }

  condition:
    any of them
}