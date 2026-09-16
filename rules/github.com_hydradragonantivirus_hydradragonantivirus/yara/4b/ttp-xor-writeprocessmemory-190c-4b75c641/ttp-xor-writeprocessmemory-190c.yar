rule TTP_XOR_WriteProcessMemory_190c {
  strings:
    $key_190c = { 4e 7e [2] 7c 5c [2] 7a 69 [2] 54 69 [2] 6b 75 }

  condition:
    any of them
}