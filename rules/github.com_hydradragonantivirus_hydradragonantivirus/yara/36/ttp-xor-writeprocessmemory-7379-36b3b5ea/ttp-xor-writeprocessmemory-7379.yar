rule TTP_XOR_WriteProcessMemory_7379 {
  strings:
    $key_7379 = { 24 0b [2] 16 29 [2] 10 1c [2] 3e 1c [2] 01 00 }

  condition:
    any of them
}