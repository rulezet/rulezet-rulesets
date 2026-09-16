rule TTP_XOR_WriteProcessMemory_7ee5 {
  strings:
    $key_7ee5 = { 29 97 [2] 1b b5 [2] 1d 80 [2] 33 80 [2] 0c 9c }

  condition:
    any of them
}