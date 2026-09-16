rule TTP_XOR_WriteProcessMemory_5479 {
  strings:
    $key_5479 = { 03 0b [2] 31 29 [2] 37 1c [2] 19 1c [2] 26 00 }

  condition:
    any of them
}