rule TTP_XOR_WriteProcessMemory_0ceb {
  strings:
    $key_0ceb = { 5b 99 [2] 69 bb [2] 6f 8e [2] 41 8e [2] 7e 92 }

  condition:
    any of them
}