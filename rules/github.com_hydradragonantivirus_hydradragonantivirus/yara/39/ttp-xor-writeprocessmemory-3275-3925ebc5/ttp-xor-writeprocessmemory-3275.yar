rule TTP_XOR_WriteProcessMemory_3275 {
  strings:
    $key_3275 = { 65 07 [2] 57 25 [2] 51 10 [2] 7f 10 [2] 40 0c }

  condition:
    any of them
}