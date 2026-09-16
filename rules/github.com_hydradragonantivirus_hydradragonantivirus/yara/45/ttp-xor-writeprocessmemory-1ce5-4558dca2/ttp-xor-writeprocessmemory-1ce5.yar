rule TTP_XOR_WriteProcessMemory_1ce5 {
  strings:
    $key_1ce5 = { 4b 97 [2] 79 b5 [2] 7f 80 [2] 51 80 [2] 6e 9c }

  condition:
    any of them
}