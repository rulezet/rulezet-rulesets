rule TTP_XOR_WriteProcessMemory_6329 {
  strings:
    $key_6329 = { 34 5b [2] 06 79 [2] 00 4c [2] 2e 4c [2] 11 50 }

  condition:
    any of them
}