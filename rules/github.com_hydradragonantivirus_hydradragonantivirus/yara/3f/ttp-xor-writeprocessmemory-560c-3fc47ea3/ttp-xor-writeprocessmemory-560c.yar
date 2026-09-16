rule TTP_XOR_WriteProcessMemory_560c {
  strings:
    $key_560c = { 01 7e [2] 33 5c [2] 35 69 [2] 1b 69 [2] 24 75 }

  condition:
    any of them
}