rule TTP_XOR_WriteProcessMemory_1be5 {
  strings:
    $key_1be5 = { 4c 97 [2] 7e b5 [2] 78 80 [2] 56 80 [2] 69 9c }

  condition:
    any of them
}