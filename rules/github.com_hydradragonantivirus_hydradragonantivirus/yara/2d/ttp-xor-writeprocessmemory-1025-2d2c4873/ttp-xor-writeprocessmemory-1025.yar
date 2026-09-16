rule TTP_XOR_WriteProcessMemory_1025 {
  strings:
    $key_1025 = { 47 57 [2] 75 75 [2] 73 40 [2] 5d 40 [2] 62 5c }

  condition:
    any of them
}