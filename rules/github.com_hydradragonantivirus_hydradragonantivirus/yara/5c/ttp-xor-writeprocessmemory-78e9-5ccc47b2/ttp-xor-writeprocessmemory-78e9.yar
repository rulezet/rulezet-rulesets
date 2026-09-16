rule TTP_XOR_WriteProcessMemory_78e9 {
  strings:
    $key_78e9 = { 2f 9b [2] 1d b9 [2] 1b 8c [2] 35 8c [2] 0a 90 }

  condition:
    any of them
}