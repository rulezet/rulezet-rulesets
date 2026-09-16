rule TTP_XOR_WriteProcessMemory_3979 {
  strings:
    $key_3979 = { 6e 0b [2] 5c 29 [2] 5a 1c [2] 74 1c [2] 4b 00 }

  condition:
    any of them
}