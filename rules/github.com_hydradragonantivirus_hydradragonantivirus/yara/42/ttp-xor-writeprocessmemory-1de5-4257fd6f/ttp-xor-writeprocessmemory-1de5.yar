rule TTP_XOR_WriteProcessMemory_1de5 {
  strings:
    $key_1de5 = { 4a 97 [2] 78 b5 [2] 7e 80 [2] 50 80 [2] 6f 9c }

  condition:
    any of them
}