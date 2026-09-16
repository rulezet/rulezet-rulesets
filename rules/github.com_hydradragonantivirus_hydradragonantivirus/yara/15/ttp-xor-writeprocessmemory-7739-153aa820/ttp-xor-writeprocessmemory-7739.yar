rule TTP_XOR_WriteProcessMemory_7739 {
  strings:
    $key_7739 = { 20 4b [2] 12 69 [2] 14 5c [2] 3a 5c [2] 05 40 }

  condition:
    any of them
}