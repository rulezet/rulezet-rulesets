rule TTP_XOR_WriteProcessMemory_64eb {
  strings:
    $key_64eb = { 33 99 [2] 01 bb [2] 07 8e [2] 29 8e [2] 16 92 }

  condition:
    any of them
}