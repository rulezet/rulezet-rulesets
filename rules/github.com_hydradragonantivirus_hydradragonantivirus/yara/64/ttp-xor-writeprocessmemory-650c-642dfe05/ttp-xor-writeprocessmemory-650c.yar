rule TTP_XOR_WriteProcessMemory_650c {
  strings:
    $key_650c = { 32 7e [2] 00 5c [2] 06 69 [2] 28 69 [2] 17 75 }

  condition:
    any of them
}