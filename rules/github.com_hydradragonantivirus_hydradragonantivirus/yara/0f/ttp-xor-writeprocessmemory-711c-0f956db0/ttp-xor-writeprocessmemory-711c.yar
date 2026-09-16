rule TTP_XOR_WriteProcessMemory_711c {
  strings:
    $key_711c = { 26 6e [2] 14 4c [2] 12 79 [2] 3c 79 [2] 03 65 }

  condition:
    any of them
}