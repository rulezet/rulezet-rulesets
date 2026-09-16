rule TTP_XOR_WriteProcessMemory_1ee5 {
  strings:
    $key_1ee5 = { 49 97 [2] 7b b5 [2] 7d 80 [2] 53 80 [2] 6c 9c }

  condition:
    any of them
}