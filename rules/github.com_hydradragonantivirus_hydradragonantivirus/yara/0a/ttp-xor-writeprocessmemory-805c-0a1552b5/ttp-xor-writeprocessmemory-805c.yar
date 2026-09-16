rule TTP_XOR_WriteProcessMemory_805c {
  strings:
    $key_805c = { d7 2e [2] e5 0c [2] e3 39 [2] cd 39 [2] f2 25 }

  condition:
    any of them
}