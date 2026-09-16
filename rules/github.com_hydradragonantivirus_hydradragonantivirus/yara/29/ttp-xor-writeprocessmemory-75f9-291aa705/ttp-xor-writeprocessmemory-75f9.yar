rule TTP_XOR_WriteProcessMemory_75f9 {
  strings:
    $key_75f9 = { 22 8b [2] 10 a9 [2] 16 9c [2] 38 9c [2] 07 80 }

  condition:
    any of them
}