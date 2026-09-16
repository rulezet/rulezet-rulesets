rule TTP_XOR_WriteProcessMemory_5df5 {
  strings:
    $key_5df5 = { 0a 87 [2] 38 a5 [2] 3e 90 [2] 10 90 [2] 2f 8c }

  condition:
    any of them
}