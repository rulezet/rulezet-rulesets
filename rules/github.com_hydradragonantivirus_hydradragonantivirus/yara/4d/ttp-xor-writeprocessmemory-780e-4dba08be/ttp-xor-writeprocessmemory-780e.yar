rule TTP_XOR_WriteProcessMemory_780e {
  strings:
    $key_780e = { 2f 7c [2] 1d 5e [2] 1b 6b [2] 35 6b [2] 0a 77 }

  condition:
    any of them
}