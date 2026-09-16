rule TTP_XOR_WriteProcessMemory_2529 {
  strings:
    $key_2529 = { 72 5b [2] 40 79 [2] 46 4c [2] 68 4c [2] 57 50 }

  condition:
    any of them
}