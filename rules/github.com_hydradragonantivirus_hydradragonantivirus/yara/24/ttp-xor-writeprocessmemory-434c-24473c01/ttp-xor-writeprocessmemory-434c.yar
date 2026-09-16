rule TTP_XOR_WriteProcessMemory_434c {
  strings:
    $key_434c = { 14 3e [2] 26 1c [2] 20 29 [2] 0e 29 [2] 31 35 }

  condition:
    any of them
}