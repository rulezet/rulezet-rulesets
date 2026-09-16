rule TTP_XOR_WriteProcessMemory_c5eb {
  strings:
    $key_c5eb = { 92 99 [2] a0 bb [2] a6 8e [2] 88 8e [2] b7 92 }

  condition:
    any of them
}