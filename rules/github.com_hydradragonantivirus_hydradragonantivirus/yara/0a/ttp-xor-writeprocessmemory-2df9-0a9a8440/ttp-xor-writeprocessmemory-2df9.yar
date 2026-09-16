rule TTP_XOR_WriteProcessMemory_2df9 {
  strings:
    $key_2df9 = { 7a 8b [2] 48 a9 [2] 4e 9c [2] 60 9c [2] 5f 80 }

  condition:
    any of them
}