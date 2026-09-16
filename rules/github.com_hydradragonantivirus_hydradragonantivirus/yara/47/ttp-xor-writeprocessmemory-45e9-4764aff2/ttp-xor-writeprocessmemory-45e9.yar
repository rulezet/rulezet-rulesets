rule TTP_XOR_WriteProcessMemory_45e9 {
  strings:
    $key_45e9 = { 12 9b [2] 20 b9 [2] 26 8c [2] 08 8c [2] 37 90 }

  condition:
    any of them
}