rule TTP_XOR_WriteProcessMemory_5ce5 {
  strings:
    $key_5ce5 = { 0b 97 [2] 39 b5 [2] 3f 80 [2] 11 80 [2] 2e 9c }

  condition:
    any of them
}