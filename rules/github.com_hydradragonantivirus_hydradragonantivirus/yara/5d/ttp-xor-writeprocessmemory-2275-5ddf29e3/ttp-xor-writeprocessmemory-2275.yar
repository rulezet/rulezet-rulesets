rule TTP_XOR_WriteProcessMemory_2275 {
  strings:
    $key_2275 = { 75 07 [2] 47 25 [2] 41 10 [2] 6f 10 [2] 50 0c }

  condition:
    any of them
}