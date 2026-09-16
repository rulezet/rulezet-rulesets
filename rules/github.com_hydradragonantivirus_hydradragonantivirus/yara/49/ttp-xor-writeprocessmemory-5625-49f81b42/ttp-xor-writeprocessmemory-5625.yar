rule TTP_XOR_WriteProcessMemory_5625 {
  strings:
    $key_5625 = { 01 57 [2] 33 75 [2] 35 40 [2] 1b 40 [2] 24 5c }

  condition:
    any of them
}