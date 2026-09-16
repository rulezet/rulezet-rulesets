rule TTP_XOR_WriteProcessMemory_0079 {
  strings:
    $key_0079 = { 57 0b [2] 65 29 [2] 63 1c [2] 4d 1c [2] 72 00 }

  condition:
    any of them
}