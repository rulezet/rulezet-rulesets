rule TTP_XOR_WriteProcessMemory_4df5 {
  strings:
    $key_4df5 = { 1a 87 [2] 28 a5 [2] 2e 90 [2] 00 90 [2] 3f 8c }

  condition:
    any of them
}