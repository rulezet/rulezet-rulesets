rule TTP_XOR_WriteProcessMemory_4429 {
  strings:
    $key_4429 = { 13 5b [2] 21 79 [2] 27 4c [2] 09 4c [2] 36 50 }

  condition:
    any of them
}