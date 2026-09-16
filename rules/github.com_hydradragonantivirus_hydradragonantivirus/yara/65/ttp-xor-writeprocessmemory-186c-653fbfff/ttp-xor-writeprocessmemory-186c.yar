rule TTP_XOR_WriteProcessMemory_186c {
  strings:
    $key_186c = { 4f 1e [2] 7d 3c [2] 7b 09 [2] 55 09 [2] 6a 15 }

  condition:
    any of them
}