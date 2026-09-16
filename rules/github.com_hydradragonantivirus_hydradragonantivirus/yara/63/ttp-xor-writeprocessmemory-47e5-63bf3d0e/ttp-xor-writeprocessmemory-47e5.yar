rule TTP_XOR_WriteProcessMemory_47e5 {
  strings:
    $key_47e5 = { 10 97 [2] 22 b5 [2] 24 80 [2] 0a 80 [2] 35 9c }

  condition:
    any of them
}