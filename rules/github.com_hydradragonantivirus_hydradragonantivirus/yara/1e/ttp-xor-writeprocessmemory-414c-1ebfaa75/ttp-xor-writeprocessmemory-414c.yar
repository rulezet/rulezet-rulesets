rule TTP_XOR_WriteProcessMemory_414c {
  strings:
    $key_414c = { 16 3e [2] 24 1c [2] 22 29 [2] 0c 29 [2] 33 35 }

  condition:
    any of them
}