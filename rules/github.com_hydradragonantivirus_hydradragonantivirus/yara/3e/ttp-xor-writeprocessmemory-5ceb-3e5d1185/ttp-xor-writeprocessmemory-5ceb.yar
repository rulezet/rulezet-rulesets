rule TTP_XOR_WriteProcessMemory_5ceb {
  strings:
    $key_5ceb = { 0b 99 [2] 39 bb [2] 3f 8e [2] 11 8e [2] 2e 92 }

  condition:
    any of them
}