rule TTP_XOR_WriteProcessMemory_356c {
  strings:
    $key_356c = { 62 1e [2] 50 3c [2] 56 09 [2] 78 09 [2] 47 15 }

  condition:
    any of them
}