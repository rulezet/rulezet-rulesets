rule TTP_XOR_WriteProcessMemory_b28c {
  strings:
    $key_b28c = { e5 fe [2] d7 dc [2] d1 e9 [2] ff e9 [2] c0 f5 }

  condition:
    any of them
}