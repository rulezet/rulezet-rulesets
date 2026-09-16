rule TTP_XOR_WriteProcessMemory_4deb {
  strings:
    $key_4deb = { 1a 99 [2] 28 bb [2] 2e 8e [2] 00 8e [2] 3f 92 }

  condition:
    any of them
}