rule TTP_XOR_WriteProcessMemory_a09b {
  strings:
    $key_a09b = { f7 e9 [2] c5 cb [2] c3 fe [2] ed fe [2] d2 e2 }

  condition:
    any of them
}