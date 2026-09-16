rule TTP_XOR_WriteProcessMemory_a69b {
  strings:
    $key_a69b = { f1 e9 [2] c3 cb [2] c5 fe [2] eb fe [2] d4 e2 }

  condition:
    any of them
}