rule TTP_XOR_WriteProcessMemory_f40b {
  strings:
    $key_f40b = { a3 79 [2] 91 5b [2] 97 6e [2] b9 6e [2] 86 72 }

  condition:
    any of them
}