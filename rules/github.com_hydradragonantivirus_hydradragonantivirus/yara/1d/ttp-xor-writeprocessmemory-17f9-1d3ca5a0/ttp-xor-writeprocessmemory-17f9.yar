rule TTP_XOR_WriteProcessMemory_17f9 {
  strings:
    $key_17f9 = { 40 8b [2] 72 a9 [2] 74 9c [2] 5a 9c [2] 65 80 }

  condition:
    any of them
}