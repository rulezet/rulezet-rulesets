rule TTP_XOR_WriteProcessMemory_c1eb {
  strings:
    $key_c1eb = { 96 99 [2] a4 bb [2] a2 8e [2] 8c 8e [2] b3 92 }

  condition:
    any of them
}