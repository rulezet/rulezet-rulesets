rule TTP_XOR_WriteProcessMemory_4660 {
  strings:
    $key_4660 = { 11 12 [2] 23 30 [2] 25 05 [2] 0b 05 [2] 34 19 }

  condition:
    any of them
}