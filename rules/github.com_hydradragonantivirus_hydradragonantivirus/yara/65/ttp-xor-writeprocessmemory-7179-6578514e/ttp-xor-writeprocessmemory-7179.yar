rule TTP_XOR_WriteProcessMemory_7179 {
  strings:
    $key_7179 = { 26 0b [2] 14 29 [2] 12 1c [2] 3c 1c [2] 03 00 }

  condition:
    any of them
}