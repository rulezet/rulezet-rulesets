rule TTP_XOR_WriteProcessMemory_1a79 {
  strings:
    $key_1a79 = { 4d 0b [2] 7f 29 [2] 79 1c [2] 57 1c [2] 68 00 }

  condition:
    any of them
}