rule TTP_XOR_WriteProcessMemory_5d2b {
  strings:
    $key_5d2b = { 0a 59 [2] 38 7b [2] 3e 4e [2] 10 4e [2] 2f 52 }

  condition:
    any of them
}