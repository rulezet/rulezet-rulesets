rule TTP_XOR_WriteProcessMemory_5d5c {
  strings:
    $key_5d5c = { 0a 2e [2] 38 0c [2] 3e 39 [2] 10 39 [2] 2f 25 }

  condition:
    any of them
}