rule TTP_XOR_WriteProcessMemory_537e {
  strings:
    $key_537e = { 04 0c [2] 36 2e [2] 30 1b [2] 1e 1b [2] 21 07 }

  condition:
    any of them
}