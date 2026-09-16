rule TTP_XOR_WriteProcessMemory_1569 {
  strings:
    $key_1569 = { 42 1b [2] 70 39 [2] 76 0c [2] 58 0c [2] 67 10 }

  condition:
    any of them
}