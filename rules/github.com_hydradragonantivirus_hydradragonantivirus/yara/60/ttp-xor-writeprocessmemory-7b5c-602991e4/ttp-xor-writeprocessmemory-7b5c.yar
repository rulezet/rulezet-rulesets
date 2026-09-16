rule TTP_XOR_WriteProcessMemory_7b5c {
  strings:
    $key_7b5c = { 2c 2e [2] 1e 0c [2] 18 39 [2] 36 39 [2] 09 25 }

  condition:
    any of them
}