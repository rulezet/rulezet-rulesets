rule TTP_XOR_WriteProcessMemory_5969 {
  strings:
    $key_5969 = { 0e 1b [2] 3c 39 [2] 3a 0c [2] 14 0c [2] 2b 10 }

  condition:
    any of them
}