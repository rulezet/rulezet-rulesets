rule TTP_XOR_WriteProcessMemory_53e5 {
  strings:
    $key_53e5 = { 04 97 [2] 36 b5 [2] 30 80 [2] 1e 80 [2] 21 9c }

  condition:
    any of them
}