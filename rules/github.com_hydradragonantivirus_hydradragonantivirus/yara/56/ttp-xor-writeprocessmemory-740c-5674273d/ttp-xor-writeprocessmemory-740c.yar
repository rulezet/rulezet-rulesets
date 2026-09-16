rule TTP_XOR_WriteProcessMemory_740c {
  strings:
    $key_740c = { 23 7e [2] 11 5c [2] 17 69 [2] 39 69 [2] 06 75 }

  condition:
    any of them
}