rule TTP_XOR_WriteProcessMemory_7779 {
  strings:
    $key_7779 = { 20 0b [2] 12 29 [2] 14 1c [2] 3a 1c [2] 05 00 }

  condition:
    any of them
}