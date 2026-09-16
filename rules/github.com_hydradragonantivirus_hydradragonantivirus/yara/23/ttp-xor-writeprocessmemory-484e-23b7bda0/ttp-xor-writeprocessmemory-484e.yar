rule TTP_XOR_WriteProcessMemory_484e {
  strings:
    $key_484e = { 1f 3c [2] 2d 1e [2] 2b 2b [2] 05 2b [2] 3a 37 }

  condition:
    any of them
}