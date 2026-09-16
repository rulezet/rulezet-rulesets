rule TTP_XOR_WriteProcessMemory_256c {
  strings:
    $key_256c = { 72 1e [2] 40 3c [2] 46 09 [2] 68 09 [2] 57 15 }

  condition:
    any of them
}