rule TTP_XOR_WriteProcessMemory_5979 {
  strings:
    $key_5979 = { 0e 0b [2] 3c 29 [2] 3a 1c [2] 14 1c [2] 2b 00 }

  condition:
    any of them
}