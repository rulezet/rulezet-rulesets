rule TTP_XOR_WriteProcessMemory_4bf9 {
  strings:
    $key_4bf9 = { 1c 8b [2] 2e a9 [2] 28 9c [2] 06 9c [2] 39 80 }

  condition:
    any of them
}