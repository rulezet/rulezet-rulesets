rule TTP_XOR_WriteProcessMemory_4af9 {
  strings:
    $key_4af9 = { 1d 8b [2] 2f a9 [2] 29 9c [2] 07 9c [2] 38 80 }

  condition:
    any of them
}