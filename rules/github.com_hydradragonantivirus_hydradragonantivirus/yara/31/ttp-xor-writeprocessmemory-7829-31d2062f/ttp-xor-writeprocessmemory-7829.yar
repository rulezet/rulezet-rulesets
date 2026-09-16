rule TTP_XOR_WriteProcessMemory_7829 {
  strings:
    $key_7829 = { 2f 5b [2] 1d 79 [2] 1b 4c [2] 35 4c [2] 0a 50 }

  condition:
    any of them
}