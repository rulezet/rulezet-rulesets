rule TTP_XOR_WriteProcessMemory_1369 {
  strings:
    $key_1369 = { 44 1b [2] 76 39 [2] 70 0c [2] 5e 0c [2] 61 10 }

  condition:
    any of them
}