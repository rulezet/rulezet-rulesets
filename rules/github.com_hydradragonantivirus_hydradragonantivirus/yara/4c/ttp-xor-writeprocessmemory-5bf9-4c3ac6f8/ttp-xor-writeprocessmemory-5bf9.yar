rule TTP_XOR_WriteProcessMemory_5bf9 {
  strings:
    $key_5bf9 = { 0c 8b [2] 3e a9 [2] 38 9c [2] 16 9c [2] 29 80 }

  condition:
    any of them
}