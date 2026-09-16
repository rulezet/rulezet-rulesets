rule TTP_XOR_WriteProcessMemory_4de5 {
  strings:
    $key_4de5 = { 1a 97 [2] 28 b5 [2] 2e 80 [2] 00 80 [2] 3f 9c }

  condition:
    any of them
}