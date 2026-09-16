rule TTP_XOR_WriteProcessMemory_b58c {
  strings:
    $key_b58c = { e2 fe [2] d0 dc [2] d6 e9 [2] f8 e9 [2] c7 f5 }

  condition:
    any of them
}