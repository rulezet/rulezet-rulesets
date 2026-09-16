rule TTP_XOR_WriteProcessMemory_64f9 {
  strings:
    $key_64f9 = { 33 8b [2] 01 a9 [2] 07 9c [2] 29 9c [2] 16 80 }

  condition:
    any of them
}