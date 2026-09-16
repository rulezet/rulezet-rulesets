rule TTP_XOR_WriteProcessMemory_54e9 {
  strings:
    $key_54e9 = { 03 9b [2] 31 b9 [2] 37 8c [2] 19 8c [2] 26 90 }

  condition:
    any of them
}