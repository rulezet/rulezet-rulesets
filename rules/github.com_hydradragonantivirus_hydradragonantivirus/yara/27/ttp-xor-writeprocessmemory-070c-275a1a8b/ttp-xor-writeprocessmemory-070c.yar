rule TTP_XOR_WriteProcessMemory_070c {
  strings:
    $key_070c = { 50 7e [2] 62 5c [2] 64 69 [2] 4a 69 [2] 75 75 }

  condition:
    any of them
}