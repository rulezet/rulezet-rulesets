rule TTP_XOR_WriteProcessMemory_6f15 {
  strings:
    $key_6f15 = { 38 67 [2] 0a 45 [2] 0c 70 [2] 22 70 [2] 1d 6c }

  condition:
    any of them
}