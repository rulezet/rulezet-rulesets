rule TTP_XOR_WriteProcessMemory_5925 {
  strings:
    $key_5925 = { 0e 57 [2] 3c 75 [2] 3a 40 [2] 14 40 [2] 2b 5c }

  condition:
    any of them
}