rule TTP_XOR_WriteProcessMemory_643e {
  strings:
    $key_643e = { 33 4c [2] 01 6e [2] 07 5b [2] 29 5b [2] 16 47 }

  condition:
    any of them
}