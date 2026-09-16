rule TTP_XOR_WriteProcessMemory_5b0c {
  strings:
    $key_5b0c = { 0c 7e [2] 3e 5c [2] 38 69 [2] 16 69 [2] 29 75 }

  condition:
    any of them
}