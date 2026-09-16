rule TTP_XOR_WriteProcessMemory_5c75 {
  strings:
    $key_5c75 = { 0b 07 [2] 39 25 [2] 3f 10 [2] 11 10 [2] 2e 0c }

  condition:
    any of them
}