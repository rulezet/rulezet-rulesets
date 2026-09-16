rule TTP_XOR_WriteProcessMemory_780c {
  strings:
    $key_780c = { 2f 7e [2] 1d 5c [2] 1b 69 [2] 35 69 [2] 0a 75 }

  condition:
    any of them
}