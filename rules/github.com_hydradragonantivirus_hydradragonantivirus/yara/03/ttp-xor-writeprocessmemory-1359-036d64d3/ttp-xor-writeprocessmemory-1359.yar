rule TTP_XOR_WriteProcessMemory_1359 {
  strings:
    $key_1359 = { 44 2b [2] 76 09 [2] 70 3c [2] 5e 3c [2] 61 20 }

  condition:
    any of them
}