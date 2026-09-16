rule TTP_XOR_WriteProcessMemory_5079 {
  strings:
    $key_5079 = { 07 0b [2] 35 29 [2] 33 1c [2] 1d 1c [2] 22 00 }

  condition:
    any of them
}