rule TTP_XOR_WriteProcessMemory_1875 {
  strings:
    $key_1875 = { 4f 07 [2] 7d 25 [2] 7b 10 [2] 55 10 [2] 6a 0c }

  condition:
    any of them
}