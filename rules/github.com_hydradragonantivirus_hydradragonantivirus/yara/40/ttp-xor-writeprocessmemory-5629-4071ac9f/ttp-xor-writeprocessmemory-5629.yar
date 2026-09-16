rule TTP_XOR_WriteProcessMemory_5629 {
  strings:
    $key_5629 = { 01 5b [2] 33 79 [2] 35 4c [2] 1b 4c [2] 24 50 }

  condition:
    any of them
}