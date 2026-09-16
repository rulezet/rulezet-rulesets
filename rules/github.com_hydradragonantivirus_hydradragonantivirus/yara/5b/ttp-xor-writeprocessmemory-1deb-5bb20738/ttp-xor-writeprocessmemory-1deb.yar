rule TTP_XOR_WriteProcessMemory_1deb {
  strings:
    $key_1deb = { 4a 99 [2] 78 bb [2] 7e 8e [2] 50 8e [2] 6f 92 }

  condition:
    any of them
}