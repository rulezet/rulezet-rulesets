rule TTP_XOR_WriteProcessMemory_1329 {
  strings:
    $key_1329 = { 44 5b [2] 76 79 [2] 70 4c [2] 5e 4c [2] 61 50 }

  condition:
    any of them
}