rule TTP_XOR_WriteProcessMemory_7ee9 {
  strings:
    $key_7ee9 = { 29 9b [2] 1b b9 [2] 1d 8c [2] 33 8c [2] 0c 90 }

  condition:
    any of them
}