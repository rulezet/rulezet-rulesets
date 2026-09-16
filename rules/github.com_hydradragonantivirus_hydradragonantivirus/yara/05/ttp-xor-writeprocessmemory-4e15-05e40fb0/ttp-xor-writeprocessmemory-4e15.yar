rule TTP_XOR_WriteProcessMemory_4e15 {
  strings:
    $key_4e15 = { 19 67 [2] 2b 45 [2] 2d 70 [2] 03 70 [2] 3c 6c }

  condition:
    any of them
}