rule TTP_XOR_WriteProcessMemory_6b79 {
  strings:
    $key_6b79 = { 3c 0b [2] 0e 29 [2] 08 1c [2] 26 1c [2] 19 00 }

  condition:
    any of them
}