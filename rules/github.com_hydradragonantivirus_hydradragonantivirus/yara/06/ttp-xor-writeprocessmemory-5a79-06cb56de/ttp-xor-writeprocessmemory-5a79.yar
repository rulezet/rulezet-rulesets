rule TTP_XOR_WriteProcessMemory_5a79 {
  strings:
    $key_5a79 = { 0d 0b [2] 3f 29 [2] 39 1c [2] 17 1c [2] 28 00 }

  condition:
    any of them
}