rule TTP_XOR_WriteProcessMemory_0deb {
  strings:
    $key_0deb = { 5a 99 [2] 68 bb [2] 6e 8e [2] 40 8e [2] 7f 92 }

  condition:
    any of them
}