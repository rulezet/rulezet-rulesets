rule TTP_XOR_WriteProcessMemory_76e9 {
  strings:
    $key_76e9 = { 21 9b [2] 13 b9 [2] 15 8c [2] 3b 8c [2] 04 90 }

  condition:
    any of them
}