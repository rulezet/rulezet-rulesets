rule TTP_XOR_WriteProcessMemory_783e {
  strings:
    $key_783e = { 2f 4c [2] 1d 6e [2] 1b 5b [2] 35 5b [2] 0a 47 }

  condition:
    any of them
}