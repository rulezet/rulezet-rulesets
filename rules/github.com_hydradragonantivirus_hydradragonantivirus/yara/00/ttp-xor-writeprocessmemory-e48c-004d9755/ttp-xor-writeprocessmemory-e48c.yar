rule TTP_XOR_WriteProcessMemory_e48c {
  strings:
    $key_e48c = { b3 fe [2] 81 dc [2] 87 e9 [2] a9 e9 [2] 96 f5 }

  condition:
    any of them
}