rule TTP_XOR_WriteProcessMemory_d7eb {
  strings:
    $key_d7eb = { 80 99 [2] b2 bb [2] b4 8e [2] 9a 8e [2] a5 92 }

  condition:
    any of them
}