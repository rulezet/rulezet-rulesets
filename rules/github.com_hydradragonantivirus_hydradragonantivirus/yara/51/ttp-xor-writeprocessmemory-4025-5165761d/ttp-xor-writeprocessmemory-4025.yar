rule TTP_XOR_WriteProcessMemory_4025 {
  strings:
    $key_4025 = { 17 57 [2] 25 75 [2] 23 40 [2] 0d 40 [2] 32 5c }

  condition:
    any of them
}