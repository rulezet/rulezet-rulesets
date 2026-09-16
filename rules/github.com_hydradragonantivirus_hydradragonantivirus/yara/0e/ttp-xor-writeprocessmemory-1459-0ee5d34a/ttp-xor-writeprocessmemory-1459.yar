rule TTP_XOR_WriteProcessMemory_1459 {
  strings:
    $key_1459 = { 43 2b [2] 71 09 [2] 77 3c [2] 59 3c [2] 66 20 }

  condition:
    any of them
}