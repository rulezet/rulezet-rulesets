rule TTP_XOR_WriteProcessMemory_2ee5 {
  strings:
    $key_2ee5 = { 79 97 [2] 4b b5 [2] 4d 80 [2] 63 80 [2] 5c 9c }

  condition:
    any of them
}