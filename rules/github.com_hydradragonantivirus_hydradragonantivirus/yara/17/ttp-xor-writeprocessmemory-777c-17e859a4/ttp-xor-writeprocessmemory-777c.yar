rule TTP_XOR_WriteProcessMemory_777c {
  strings:
    $key_777c = { 20 0e [2] 12 2c [2] 14 19 [2] 3a 19 [2] 05 05 }

  condition:
    any of them
}