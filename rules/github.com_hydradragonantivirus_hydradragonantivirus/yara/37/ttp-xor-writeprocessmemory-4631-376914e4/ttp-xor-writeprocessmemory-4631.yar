rule TTP_XOR_WriteProcessMemory_4631 {
  strings:
    $key_4631 = { 11 43 [2] 23 61 [2] 25 54 [2] 0b 54 [2] 34 48 }

  condition:
    any of them
}