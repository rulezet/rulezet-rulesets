rule TTP_XOR_WriteProcessMemory_730c {
  strings:
    $key_730c = { 24 7e [2] 16 5c [2] 10 69 [2] 3e 69 [2] 01 75 }

  condition:
    any of them
}