rule TTP_XOR_WriteProcessMemory_25f9 {
  strings:
    $key_25f9 = { 72 8b [2] 40 a9 [2] 46 9c [2] 68 9c [2] 57 80 }

  condition:
    any of them
}