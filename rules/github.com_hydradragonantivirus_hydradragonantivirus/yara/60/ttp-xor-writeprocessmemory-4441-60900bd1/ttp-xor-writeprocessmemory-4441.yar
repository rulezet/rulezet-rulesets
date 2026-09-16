rule TTP_XOR_WriteProcessMemory_4441 {
  strings:
    $key_4441 = { 13 33 [2] 21 11 [2] 27 24 [2] 09 24 [2] 36 38 }

  condition:
    any of them
}