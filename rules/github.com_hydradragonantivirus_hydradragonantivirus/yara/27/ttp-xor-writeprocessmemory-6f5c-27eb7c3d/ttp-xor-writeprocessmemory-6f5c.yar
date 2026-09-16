rule TTP_XOR_WriteProcessMemory_6f5c {
  strings:
    $key_6f5c = { 38 2e [2] 0a 0c [2] 0c 39 [2] 22 39 [2] 1d 25 }

  condition:
    any of them
}