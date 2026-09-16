rule TTP_XOR_WriteProcessMemory_453c {
  strings:
    $key_453c = { 12 4e [2] 20 6c [2] 26 59 [2] 08 59 [2] 37 45 }

  condition:
    any of them
}