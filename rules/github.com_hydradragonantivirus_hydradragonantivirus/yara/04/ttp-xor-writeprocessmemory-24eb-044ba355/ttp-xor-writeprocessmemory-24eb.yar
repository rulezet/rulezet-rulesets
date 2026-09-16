rule TTP_XOR_WriteProcessMemory_24eb {
  strings:
    $key_24eb = { 73 99 [2] 41 bb [2] 47 8e [2] 69 8e [2] 56 92 }

  condition:
    any of them
}