rule TTP_XOR_WriteProcessMemory_2075 {
  strings:
    $key_2075 = { 77 07 [2] 45 25 [2] 43 10 [2] 6d 10 [2] 52 0c }

  condition:
    any of them
}