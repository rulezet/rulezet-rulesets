rule TTP_XOR_WriteProcessMemory_45f9 {
  strings:
    $key_45f9 = { 12 8b [2] 20 a9 [2] 26 9c [2] 08 9c [2] 37 80 }

  condition:
    any of them
}