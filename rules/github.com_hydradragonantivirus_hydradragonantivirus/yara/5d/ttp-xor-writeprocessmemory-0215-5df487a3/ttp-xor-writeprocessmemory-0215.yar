rule TTP_XOR_WriteProcessMemory_0215 {
  strings:
    $key_0215 = { 55 67 [2] 67 45 [2] 61 70 [2] 4f 70 [2] 70 6c }

  condition:
    any of them
}