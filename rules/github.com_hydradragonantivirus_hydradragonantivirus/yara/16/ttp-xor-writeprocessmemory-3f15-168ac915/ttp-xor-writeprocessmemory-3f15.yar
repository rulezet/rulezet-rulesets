rule TTP_XOR_WriteProcessMemory_3f15 {
  strings:
    $key_3f15 = { 68 67 [2] 5a 45 [2] 5c 70 [2] 72 70 [2] 4d 6c }

  condition:
    any of them
}