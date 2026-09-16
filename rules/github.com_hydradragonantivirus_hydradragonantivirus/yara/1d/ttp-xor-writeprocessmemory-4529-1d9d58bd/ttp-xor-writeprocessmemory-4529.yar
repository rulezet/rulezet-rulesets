rule TTP_XOR_WriteProcessMemory_4529 {
  strings:
    $key_4529 = { 12 5b [2] 20 79 [2] 26 4c [2] 08 4c [2] 37 50 }

  condition:
    any of them
}