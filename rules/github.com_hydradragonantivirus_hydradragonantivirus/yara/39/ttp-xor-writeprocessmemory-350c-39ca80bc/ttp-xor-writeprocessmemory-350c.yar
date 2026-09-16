rule TTP_XOR_WriteProcessMemory_350c {
  strings:
    $key_350c = { 62 7e [2] 50 5c [2] 56 69 [2] 78 69 [2] 47 75 }

  condition:
    any of them
}