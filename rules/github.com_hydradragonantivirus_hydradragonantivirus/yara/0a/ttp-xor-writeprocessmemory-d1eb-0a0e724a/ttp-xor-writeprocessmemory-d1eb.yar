rule TTP_XOR_WriteProcessMemory_d1eb {
  strings:
    $key_d1eb = { 86 99 [2] b4 bb [2] b2 8e [2] 9c 8e [2] a3 92 }

  condition:
    any of them
}