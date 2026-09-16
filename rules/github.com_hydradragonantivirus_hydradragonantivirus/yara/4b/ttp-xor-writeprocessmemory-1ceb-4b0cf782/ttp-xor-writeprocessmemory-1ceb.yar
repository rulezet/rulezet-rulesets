rule TTP_XOR_WriteProcessMemory_1ceb {
  strings:
    $key_1ceb = { 4b 99 [2] 79 bb [2] 7f 8e [2] 51 8e [2] 6e 92 }

  condition:
    any of them
}