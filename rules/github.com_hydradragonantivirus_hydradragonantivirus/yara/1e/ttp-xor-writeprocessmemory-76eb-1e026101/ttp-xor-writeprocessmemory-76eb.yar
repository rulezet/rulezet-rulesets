rule TTP_XOR_WriteProcessMemory_76eb {
  strings:
    $key_76eb = { 21 99 [2] 13 bb [2] 15 8e [2] 3b 8e [2] 04 92 }

  condition:
    any of them
}