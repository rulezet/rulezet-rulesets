rule TTP_XOR_WriteProcessMemory_3b75 {
  strings:
    $key_3b75 = { 6c 07 [2] 5e 25 [2] 58 10 [2] 76 10 [2] 49 0c }

  condition:
    any of them
}