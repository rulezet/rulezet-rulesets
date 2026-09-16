rule TTP_XOR_WriteProcessMemory_d3eb {
  strings:
    $key_d3eb = { 84 99 [2] b6 bb [2] b0 8e [2] 9e 8e [2] a1 92 }

  condition:
    any of them
}