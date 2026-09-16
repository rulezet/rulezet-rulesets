rule TTP_XOR_WriteProcessMemory_1df5 {
  strings:
    $key_1df5 = { 4a 87 [2] 78 a5 [2] 7e 90 [2] 50 90 [2] 6f 8c }

  condition:
    any of them
}