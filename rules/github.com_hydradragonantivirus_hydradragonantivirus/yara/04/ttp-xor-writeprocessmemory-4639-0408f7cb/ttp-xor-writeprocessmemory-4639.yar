rule TTP_XOR_WriteProcessMemory_4639 {
  strings:
    $key_4639 = { 11 4b [2] 23 69 [2] 25 5c [2] 0b 5c [2] 34 40 }

  condition:
    any of them
}