rule TTP_XOR_WriteProcessMemory_4ceb {
  strings:
    $key_4ceb = { 1b 99 [2] 29 bb [2] 2f 8e [2] 01 8e [2] 3e 92 }

  condition:
    any of them
}