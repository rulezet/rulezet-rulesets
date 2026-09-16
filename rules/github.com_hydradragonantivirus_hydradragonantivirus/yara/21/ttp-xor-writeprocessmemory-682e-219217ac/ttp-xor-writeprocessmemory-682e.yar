rule TTP_XOR_WriteProcessMemory_682e {
  strings:
    $key_682e = { 3f 5c [2] 0d 7e [2] 0b 4b [2] 25 4b [2] 1a 57 }

  condition:
    any of them
}