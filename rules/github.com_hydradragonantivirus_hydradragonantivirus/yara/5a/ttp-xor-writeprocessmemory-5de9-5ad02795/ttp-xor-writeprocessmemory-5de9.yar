rule TTP_XOR_WriteProcessMemory_5de9 {
  strings:
    $key_5de9 = { 0a 9b [2] 38 b9 [2] 3e 8c [2] 10 8c [2] 2f 90 }

  condition:
    any of them
}