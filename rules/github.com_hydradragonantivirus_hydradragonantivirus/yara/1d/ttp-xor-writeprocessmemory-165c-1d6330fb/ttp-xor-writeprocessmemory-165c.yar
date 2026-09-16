rule TTP_XOR_WriteProcessMemory_165c {
  strings:
    $key_165c = { 41 2e [2] 73 0c [2] 75 39 [2] 5b 39 [2] 64 25 }

  condition:
    any of them
}