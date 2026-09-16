rule TTP_XOR_WriteProcessMemory_c28c {
  strings:
    $key_c28c = { 95 fe [2] a7 dc [2] a1 e9 [2] 8f e9 [2] b0 f5 }

  condition:
    any of them
}