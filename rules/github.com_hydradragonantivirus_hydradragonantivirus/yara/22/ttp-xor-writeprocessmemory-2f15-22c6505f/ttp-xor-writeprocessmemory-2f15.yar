rule TTP_XOR_WriteProcessMemory_2f15 {
  strings:
    $key_2f15 = { 78 67 [2] 4a 45 [2] 4c 70 [2] 62 70 [2] 5d 6c }

  condition:
    any of them
}