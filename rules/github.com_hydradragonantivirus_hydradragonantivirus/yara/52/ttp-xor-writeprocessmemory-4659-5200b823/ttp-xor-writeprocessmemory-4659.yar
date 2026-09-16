rule TTP_XOR_WriteProcessMemory_4659 {
  strings:
    $key_4659 = { 11 2b [2] 23 09 [2] 25 3c [2] 0b 3c [2] 34 20 }

  condition:
    any of them
}