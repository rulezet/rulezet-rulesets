rule TTP_XOR_WriteProcessMemory_7479 {
  strings:
    $key_7479 = { 23 0b [2] 11 29 [2] 17 1c [2] 39 1c [2] 06 00 }

  condition:
    any of them
}