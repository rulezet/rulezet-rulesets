rule TTP_XOR_WriteProcessMemory_0f25 {
  strings:
    $key_0f25 = { 58 57 [2] 6a 75 [2] 6c 40 [2] 42 40 [2] 7d 5c }

  condition:
    any of them
}