rule TTP_XOR_WriteProcessMemory_f54b {
  strings:
    $key_f54b = { a2 39 [2] 90 1b [2] 96 2e [2] b8 2e [2] 87 32 }

  condition:
    any of them
}