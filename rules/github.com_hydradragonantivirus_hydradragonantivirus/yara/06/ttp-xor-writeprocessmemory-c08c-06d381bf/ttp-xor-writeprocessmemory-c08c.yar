rule TTP_XOR_WriteProcessMemory_c08c {
  strings:
    $key_c08c = { 97 fe [2] a5 dc [2] a3 e9 [2] 8d e9 [2] b2 f5 }

  condition:
    any of them
}