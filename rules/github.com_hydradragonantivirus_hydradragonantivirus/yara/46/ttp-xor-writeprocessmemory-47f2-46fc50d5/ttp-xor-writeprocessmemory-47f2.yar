rule TTP_XOR_WriteProcessMemory_47f2 {
  strings:
    $key_47f2 = { 10 80 [2] 22 a2 [2] 24 97 [2] 0a 97 [2] 35 8b }

  condition:
    any of them
}