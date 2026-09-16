rule TTP_XOR_WriteProcessMemory_17e5 {
  strings:
    $key_17e5 = { 40 97 [2] 72 b5 [2] 74 80 [2] 5a 80 [2] 65 9c }

  condition:
    any of them
}