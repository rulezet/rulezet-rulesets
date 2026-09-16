rule TTP_XOR_WriteProcessMemory_5d1c {
  strings:
    $key_5d1c = { 0a 6e [2] 38 4c [2] 3e 79 [2] 10 79 [2] 2f 65 }

  condition:
    any of them
}