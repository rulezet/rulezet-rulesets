rule TTP_XOR_WriteProcessMemory_71e9 {
  strings:
    $key_71e9 = { 26 9b [2] 14 b9 [2] 12 8c [2] 3c 8c [2] 03 90 }

  condition:
    any of them
}