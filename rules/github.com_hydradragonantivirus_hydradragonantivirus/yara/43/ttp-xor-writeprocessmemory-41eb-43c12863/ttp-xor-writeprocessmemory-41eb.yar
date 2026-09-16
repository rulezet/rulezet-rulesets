rule TTP_XOR_WriteProcessMemory_41eb {
  strings:
    $key_41eb = { 16 99 [2] 24 bb [2] 22 8e [2] 0c 8e [2] 33 92 }

  condition:
    any of them
}