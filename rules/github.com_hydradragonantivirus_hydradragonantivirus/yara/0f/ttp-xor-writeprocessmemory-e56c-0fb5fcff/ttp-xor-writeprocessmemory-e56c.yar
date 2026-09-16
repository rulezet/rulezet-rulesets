rule TTP_XOR_WriteProcessMemory_e56c {
  strings:
    $key_e56c = { b2 1e [2] 80 3c [2] 86 09 [2] a8 09 [2] 97 15 }

  condition:
    any of them
}