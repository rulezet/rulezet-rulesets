rule TTP_XOR_WriteProcessMemory_6629 {
  strings:
    $key_6629 = { 31 5b [2] 03 79 [2] 05 4c [2] 2b 4c [2] 14 50 }

  condition:
    any of them
}