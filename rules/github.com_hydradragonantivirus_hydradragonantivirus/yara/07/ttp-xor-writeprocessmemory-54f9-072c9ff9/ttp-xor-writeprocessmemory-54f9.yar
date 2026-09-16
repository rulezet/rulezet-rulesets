rule TTP_XOR_WriteProcessMemory_54f9 {
  strings:
    $key_54f9 = { 03 8b [2] 31 a9 [2] 37 9c [2] 19 9c [2] 26 80 }

  condition:
    any of them
}