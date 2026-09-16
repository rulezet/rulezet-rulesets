rule TTP_XOR_WriteProcessMemory_7b1c {
  strings:
    $key_7b1c = { 2c 6e [2] 1e 4c [2] 18 79 [2] 36 79 [2] 09 65 }

  condition:
    any of them
}