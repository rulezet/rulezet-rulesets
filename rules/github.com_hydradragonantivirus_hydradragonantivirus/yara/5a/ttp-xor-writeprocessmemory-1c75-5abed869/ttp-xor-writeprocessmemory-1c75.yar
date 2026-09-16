rule TTP_XOR_WriteProcessMemory_1c75 {
  strings:
    $key_1c75 = { 4b 07 [2] 79 25 [2] 7f 10 [2] 51 10 [2] 6e 0c }

  condition:
    any of them
}