rule TTP_XOR_WriteProcessMemory_17e9 {
  strings:
    $key_17e9 = { 40 9b [2] 72 b9 [2] 74 8c [2] 5a 8c [2] 65 90 }

  condition:
    any of them
}