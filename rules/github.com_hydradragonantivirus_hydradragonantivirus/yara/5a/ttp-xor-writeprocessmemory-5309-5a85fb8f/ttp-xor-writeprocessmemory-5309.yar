rule TTP_XOR_WriteProcessMemory_5309 {
  strings:
    $key_5309 = { 04 7b [2] 36 59 [2] 30 6c [2] 1e 6c [2] 21 70 }

  condition:
    any of them
}