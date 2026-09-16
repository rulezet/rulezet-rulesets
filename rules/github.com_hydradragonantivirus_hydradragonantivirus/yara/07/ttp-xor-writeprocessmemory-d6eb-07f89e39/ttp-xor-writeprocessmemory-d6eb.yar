rule TTP_XOR_WriteProcessMemory_d6eb {
  strings:
    $key_d6eb = { 81 99 [2] b3 bb [2] b5 8e [2] 9b 8e [2] a4 92 }

  condition:
    any of them
}