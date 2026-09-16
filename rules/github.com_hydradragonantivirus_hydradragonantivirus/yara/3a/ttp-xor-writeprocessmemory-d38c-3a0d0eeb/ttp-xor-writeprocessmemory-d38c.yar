rule TTP_XOR_WriteProcessMemory_d38c {
  strings:
    $key_d38c = { 84 fe [2] b6 dc [2] b0 e9 [2] 9e e9 [2] a1 f5 }

  condition:
    any of them
}