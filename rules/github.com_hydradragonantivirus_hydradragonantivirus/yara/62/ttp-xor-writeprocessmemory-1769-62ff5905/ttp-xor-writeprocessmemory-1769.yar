rule TTP_XOR_WriteProcessMemory_1769 {
  strings:
    $key_1769 = { 40 1b [2] 72 39 [2] 74 0c [2] 5a 0c [2] 65 10 }

  condition:
    any of them
}