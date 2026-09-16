rule TTP_XOR_WriteProcessMemory_5b6c {
  strings:
    $key_5b6c = { 0c 1e [2] 3e 3c [2] 38 09 [2] 16 09 [2] 29 15 }

  condition:
    any of them
}