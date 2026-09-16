rule TTP_XOR_WriteProcessMemory_3df5 {
  strings:
    $key_3df5 = { 6a 87 [2] 58 a5 [2] 5e 90 [2] 70 90 [2] 4f 8c }

  condition:
    any of them
}