rule TTP_XOR_WriteProcessMemory_64e9 {
  strings:
    $key_64e9 = { 33 9b [2] 01 b9 [2] 07 8c [2] 29 8c [2] 16 90 }

  condition:
    any of them
}