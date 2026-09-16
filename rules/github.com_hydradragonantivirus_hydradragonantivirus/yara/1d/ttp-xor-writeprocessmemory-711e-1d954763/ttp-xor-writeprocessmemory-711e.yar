rule TTP_XOR_WriteProcessMemory_711e {
  strings:
    $key_711e = { 26 6c [2] 14 4e [2] 12 7b [2] 3c 7b [2] 03 67 }

  condition:
    any of them
}