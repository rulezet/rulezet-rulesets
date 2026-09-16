rule TTP_XOR_WriteProcessMemory_3df9 {
  strings:
    $key_3df9 = { 6a 8b [2] 58 a9 [2] 5e 9c [2] 70 9c [2] 4f 80 }

  condition:
    any of them
}