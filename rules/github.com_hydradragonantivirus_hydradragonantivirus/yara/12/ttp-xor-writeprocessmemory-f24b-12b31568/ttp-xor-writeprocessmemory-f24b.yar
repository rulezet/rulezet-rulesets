rule TTP_XOR_WriteProcessMemory_f24b {
  strings:
    $key_f24b = { a5 39 [2] 97 1b [2] 91 2e [2] bf 2e [2] 80 32 }

  condition:
    any of them
}