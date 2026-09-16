rule TTP_XOR_WriteProcessMemory_477e {
  strings:
    $key_477e = { 10 0c [2] 22 2e [2] 24 1b [2] 0a 1b [2] 35 07 }

  condition:
    any of them
}