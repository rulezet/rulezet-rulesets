rule TTP_XOR_WriteProcessMemory_781c {
  strings:
    $key_781c = { 2f 6e [2] 1d 4c [2] 1b 79 [2] 35 79 [2] 0a 65 }

  condition:
    any of them
}