rule TTP_XOR_WriteProcessMemory_c0eb {
  strings:
    $key_c0eb = { 97 99 [2] a5 bb [2] a3 8e [2] 8d 8e [2] b2 92 }

  condition:
    any of them
}