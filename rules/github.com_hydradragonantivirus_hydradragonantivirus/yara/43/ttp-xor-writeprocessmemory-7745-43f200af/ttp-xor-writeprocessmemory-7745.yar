rule TTP_XOR_WriteProcessMemory_7745 {
  strings:
    $key_7745 = { 20 37 [2] 12 15 [2] 14 20 [2] 3a 20 [2] 05 3c }

  condition:
    any of them
}