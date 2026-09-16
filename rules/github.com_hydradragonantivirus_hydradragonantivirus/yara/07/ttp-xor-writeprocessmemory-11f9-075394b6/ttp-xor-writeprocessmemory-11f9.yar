rule TTP_XOR_WriteProcessMemory_11f9 {
  strings:
    $key_11f9 = { 46 8b [2] 74 a9 [2] 72 9c [2] 5c 9c [2] 63 80 }

  condition:
    any of them
}