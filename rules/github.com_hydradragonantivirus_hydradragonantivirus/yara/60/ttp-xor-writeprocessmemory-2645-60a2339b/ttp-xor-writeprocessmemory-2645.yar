rule TTP_XOR_WriteProcessMemory_2645 {
  strings:
    $key_2645 = { 71 37 [2] 43 15 [2] 45 20 [2] 6b 20 [2] 54 3c }

  condition:
    any of them
}