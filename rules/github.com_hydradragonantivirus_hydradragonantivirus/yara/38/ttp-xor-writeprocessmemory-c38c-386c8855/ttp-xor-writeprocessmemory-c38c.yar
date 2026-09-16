rule TTP_XOR_WriteProcessMemory_c38c {
  strings:
    $key_c38c = { 94 fe [2] a6 dc [2] a0 e9 [2] 8e e9 [2] b1 f5 }

  condition:
    any of them
}