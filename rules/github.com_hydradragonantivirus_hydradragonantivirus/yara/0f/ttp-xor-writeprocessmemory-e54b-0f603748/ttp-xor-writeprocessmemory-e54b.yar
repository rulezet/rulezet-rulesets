rule TTP_XOR_WriteProcessMemory_e54b {
  strings:
    $key_e54b = { b2 39 [2] 80 1b [2] 86 2e [2] a8 2e [2] 97 32 }

  condition:
    any of them
}