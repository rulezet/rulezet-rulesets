rule TTP_XOR_WriteProcessMemory_a78c {
  strings:
    $key_a78c = { f0 fe [2] c2 dc [2] c4 e9 [2] ea e9 [2] d5 f5 }

  condition:
    any of them
}