rule TTP_XOR_WriteProcessMemory_0f15 {
  strings:
    $key_0f15 = { 58 67 [2] 6a 45 [2] 6c 70 [2] 42 70 [2] 7d 6c }

  condition:
    any of them
}