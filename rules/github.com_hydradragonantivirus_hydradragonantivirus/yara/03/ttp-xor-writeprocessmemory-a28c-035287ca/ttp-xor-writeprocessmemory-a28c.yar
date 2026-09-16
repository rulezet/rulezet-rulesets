rule TTP_XOR_WriteProcessMemory_a28c {
  strings:
    $key_a28c = { f5 fe [2] c7 dc [2] c1 e9 [2] ef e9 [2] d0 f5 }

  condition:
    any of them
}