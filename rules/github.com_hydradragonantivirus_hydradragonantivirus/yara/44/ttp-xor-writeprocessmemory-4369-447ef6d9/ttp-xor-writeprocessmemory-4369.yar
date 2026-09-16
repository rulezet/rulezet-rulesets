rule TTP_XOR_WriteProcessMemory_4369 {
  strings:
    $key_4369 = { 14 1b [2] 26 39 [2] 20 0c [2] 0e 0c [2] 31 10 }

  condition:
    any of them
}