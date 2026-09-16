rule TTP_XOR_WriteProcessMemory_d08c {
  strings:
    $key_d08c = { 87 fe [2] b5 dc [2] b3 e9 [2] 9d e9 [2] a2 f5 }

  condition:
    any of them
}