rule TTP_XOR_WriteProcessMemory_f47e {
  strings:
    $key_f47e = { a3 0c [2] 91 2e [2] 97 1b [2] b9 1b [2] 86 07 }

  condition:
    any of them
}