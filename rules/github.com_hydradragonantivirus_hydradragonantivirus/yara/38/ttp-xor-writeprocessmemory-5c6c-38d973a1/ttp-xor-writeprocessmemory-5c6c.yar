rule TTP_XOR_WriteProcessMemory_5c6c {
  strings:
    $key_5c6c = { 0b 1e [2] 39 3c [2] 3f 09 [2] 11 09 [2] 2e 15 }

  condition:
    any of them
}