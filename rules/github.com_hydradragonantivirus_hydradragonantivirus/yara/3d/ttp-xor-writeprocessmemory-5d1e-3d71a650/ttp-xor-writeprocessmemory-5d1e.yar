rule TTP_XOR_WriteProcessMemory_5d1e {
  strings:
    $key_5d1e = { 0a 6c [2] 38 4e [2] 3e 7b [2] 10 7b [2] 2f 67 }

  condition:
    any of them
}