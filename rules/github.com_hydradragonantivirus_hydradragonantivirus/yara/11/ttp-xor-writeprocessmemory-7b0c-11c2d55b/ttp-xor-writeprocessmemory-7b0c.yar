rule TTP_XOR_WriteProcessMemory_7b0c {
  strings:
    $key_7b0c = { 2c 7e [2] 1e 5c [2] 18 69 [2] 36 69 [2] 09 75 }

  condition:
    any of them
}