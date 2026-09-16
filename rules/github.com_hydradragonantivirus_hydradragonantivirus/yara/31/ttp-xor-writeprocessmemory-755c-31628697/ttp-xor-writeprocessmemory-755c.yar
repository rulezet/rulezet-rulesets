rule TTP_XOR_WriteProcessMemory_755c {
  strings:
    $key_755c = { 22 2e [2] 10 0c [2] 16 39 [2] 38 39 [2] 07 25 }

  condition:
    any of them
}