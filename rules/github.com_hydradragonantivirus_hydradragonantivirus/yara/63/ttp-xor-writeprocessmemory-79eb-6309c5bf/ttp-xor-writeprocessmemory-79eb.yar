rule TTP_XOR_WriteProcessMemory_79eb {
  strings:
    $key_79eb = { 2e 99 [2] 1c bb [2] 1a 8e [2] 34 8e [2] 0b 92 }

  condition:
    any of them
}