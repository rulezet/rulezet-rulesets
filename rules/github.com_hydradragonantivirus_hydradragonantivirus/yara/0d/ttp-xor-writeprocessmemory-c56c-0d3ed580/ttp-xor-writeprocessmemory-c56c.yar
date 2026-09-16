rule TTP_XOR_WriteProcessMemory_c56c {
  strings:
    $key_c56c = { 92 1e [2] a0 3c [2] a6 09 [2] 88 09 [2] b7 15 }

  condition:
    any of them
}