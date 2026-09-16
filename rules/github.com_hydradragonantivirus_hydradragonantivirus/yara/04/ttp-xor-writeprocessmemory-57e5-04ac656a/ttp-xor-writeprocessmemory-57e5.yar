rule TTP_XOR_WriteProcessMemory_57e5 {
  strings:
    $key_57e5 = { 00 97 [2] 32 b5 [2] 34 80 [2] 1a 80 [2] 25 9c }

  condition:
    any of them
}