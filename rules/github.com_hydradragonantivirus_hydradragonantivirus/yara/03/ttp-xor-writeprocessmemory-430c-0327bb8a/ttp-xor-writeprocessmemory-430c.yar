rule TTP_XOR_WriteProcessMemory_430c {
  strings:
    $key_430c = { 14 7e [2] 26 5c [2] 20 69 [2] 0e 69 [2] 31 75 }

  condition:
    any of them
}