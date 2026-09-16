rule TTP_XOR_WriteProcessMemory_3ce5 {
  strings:
    $key_3ce5 = { 6b 97 [2] 59 b5 [2] 5f 80 [2] 71 80 [2] 4e 9c }

  condition:
    any of them
}