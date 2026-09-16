rule TTP_XOR_WriteProcessMemory_56f9 {
  strings:
    $key_56f9 = { 01 8b [2] 33 a9 [2] 35 9c [2] 1b 9c [2] 24 80 }

  condition:
    any of them
}