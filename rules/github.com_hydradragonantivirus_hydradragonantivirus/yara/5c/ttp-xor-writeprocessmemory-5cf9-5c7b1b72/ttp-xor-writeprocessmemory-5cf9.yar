rule TTP_XOR_WriteProcessMemory_5cf9 {
  strings:
    $key_5cf9 = { 0b 8b [2] 39 a9 [2] 3f 9c [2] 11 9c [2] 2e 80 }

  condition:
    any of them
}