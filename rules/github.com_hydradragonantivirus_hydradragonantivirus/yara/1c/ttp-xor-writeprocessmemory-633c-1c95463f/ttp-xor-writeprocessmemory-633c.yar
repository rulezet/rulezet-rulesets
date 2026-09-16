rule TTP_XOR_WriteProcessMemory_633c {
  strings:
    $key_633c = { 34 4e [2] 06 6c [2] 00 59 [2] 2e 59 [2] 11 45 }

  condition:
    any of them
}