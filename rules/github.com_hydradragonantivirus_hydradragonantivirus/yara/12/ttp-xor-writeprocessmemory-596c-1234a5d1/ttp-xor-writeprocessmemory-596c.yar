rule TTP_XOR_WriteProcessMemory_596c {
  strings:
    $key_596c = { 0e 1e [2] 3c 3c [2] 3a 09 [2] 14 09 [2] 2b 15 }

  condition:
    any of them
}