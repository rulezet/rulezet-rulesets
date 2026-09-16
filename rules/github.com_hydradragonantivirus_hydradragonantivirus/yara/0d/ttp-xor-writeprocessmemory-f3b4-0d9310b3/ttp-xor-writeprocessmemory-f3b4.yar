rule TTP_XOR_WriteProcessMemory_f3b4 {
  strings:
    $key_f3b4 = { a4 c6 [2] 96 e4 [2] 90 d1 [2] be d1 [2] 81 cd }

  condition:
    any of them
}