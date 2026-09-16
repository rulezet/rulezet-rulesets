rule TTP_XOR_WriteProcessMemory_47f9 {
  strings:
    $key_47f9 = { 10 8b [2] 22 a9 [2] 24 9c [2] 0a 9c [2] 35 80 }

  condition:
    any of them
}