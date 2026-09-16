rule TTP_XOR_WriteProcessMemory_1729 {
  strings:
    $key_1729 = { 40 5b [2] 72 79 [2] 74 4c [2] 5a 4c [2] 65 50 }

  condition:
    any of them
}