rule TTP_XOR_WriteProcessMemory_944b {
  strings:
    $key_944b = { c3 39 [2] f1 1b [2] f7 2e [2] d9 2e [2] e6 32 }

  condition:
    any of them
}