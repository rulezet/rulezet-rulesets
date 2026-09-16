rule TTP_XOR_WriteProcessMemory_6df9 {
  strings:
    $key_6df9 = { 3a 8b [2] 08 a9 [2] 0e 9c [2] 20 9c [2] 1f 80 }

  condition:
    any of them
}