rule TTP_XOR_WriteProcessMemory_647e {
  strings:
    $key_647e = { 33 0c [2] 01 2e [2] 07 1b [2] 29 1b [2] 16 07 }

  condition:
    any of them
}