rule TTP_XOR_WriteProcessMemory_7bf9 {
  strings:
    $key_7bf9 = { 2c 8b [2] 1e a9 [2] 18 9c [2] 36 9c [2] 09 80 }

  condition:
    any of them
}