rule TTP_XOR_WriteProcessMemory_5d4c {
  strings:
    $key_5d4c = { 0a 3e [2] 38 1c [2] 3e 29 [2] 10 29 [2] 2f 35 }

  condition:
    any of them
}