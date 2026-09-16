rule TTP_XOR_WriteProcessMemory_f44b {
  strings:
    $key_f44b = { a3 39 [2] 91 1b [2] 97 2e [2] b9 2e [2] 86 32 }

  condition:
    any of them
}