rule TTP_XOR_WriteProcessMemory_437e {
  strings:
    $key_437e = { 14 0c [2] 26 2e [2] 20 1b [2] 0e 1b [2] 31 07 }

  condition:
    any of them
}