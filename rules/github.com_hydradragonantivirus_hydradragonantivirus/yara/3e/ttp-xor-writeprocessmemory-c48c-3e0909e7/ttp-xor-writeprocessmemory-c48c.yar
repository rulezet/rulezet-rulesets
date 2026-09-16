rule TTP_XOR_WriteProcessMemory_c48c {
  strings:
    $key_c48c = { 93 fe [2] a1 dc [2] a7 e9 [2] 89 e9 [2] b6 f5 }

  condition:
    any of them
}