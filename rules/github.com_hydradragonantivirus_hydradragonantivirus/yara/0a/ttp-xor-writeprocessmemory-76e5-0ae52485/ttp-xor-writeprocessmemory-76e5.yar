rule TTP_XOR_WriteProcessMemory_76e5 {
  strings:
    $key_76e5 = { 21 97 [2] 13 b5 [2] 15 80 [2] 3b 80 [2] 04 9c }

  condition:
    any of them
}