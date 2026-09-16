rule TTP_XOR_WriteProcessMemory_37e5 {
  strings:
    $key_37e5 = { 60 97 [2] 52 b5 [2] 54 80 [2] 7a 80 [2] 45 9c }

  condition:
    any of them
}