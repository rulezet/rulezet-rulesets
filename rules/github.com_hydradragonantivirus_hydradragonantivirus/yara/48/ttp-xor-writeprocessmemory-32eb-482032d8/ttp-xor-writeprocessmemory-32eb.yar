rule TTP_XOR_WriteProcessMemory_32eb {
  strings:
    $key_32eb = { 65 99 [2] 57 bb [2] 51 8e [2] 7f 8e [2] 40 92 }

  condition:
    any of them
}