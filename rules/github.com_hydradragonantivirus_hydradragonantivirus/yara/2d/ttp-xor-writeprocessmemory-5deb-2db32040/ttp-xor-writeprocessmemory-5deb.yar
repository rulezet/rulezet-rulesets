rule TTP_XOR_WriteProcessMemory_5deb {
  strings:
    $key_5deb = { 0a 99 [2] 38 bb [2] 3e 8e [2] 10 8e [2] 2f 92 }

  condition:
    any of them
}