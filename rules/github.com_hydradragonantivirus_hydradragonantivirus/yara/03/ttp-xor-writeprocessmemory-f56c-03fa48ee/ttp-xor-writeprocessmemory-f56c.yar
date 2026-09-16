rule TTP_XOR_WriteProcessMemory_f56c {
  strings:
    $key_f56c = { a2 1e [2] 90 3c [2] 96 09 [2] b8 09 [2] 87 15 }

  condition:
    any of them
}