rule TTP_XOR_WriteProcessMemory_56e9 {
  strings:
    $key_56e9 = { 01 9b [2] 33 b9 [2] 35 8c [2] 1b 8c [2] 24 90 }

  condition:
    any of them
}