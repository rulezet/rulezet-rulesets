rule TTP_XOR_WriteProcessMemory_59f9 {
  strings:
    $key_59f9 = { 0e 8b [2] 3c a9 [2] 3a 9c [2] 14 9c [2] 2b 80 }

  condition:
    any of them
}