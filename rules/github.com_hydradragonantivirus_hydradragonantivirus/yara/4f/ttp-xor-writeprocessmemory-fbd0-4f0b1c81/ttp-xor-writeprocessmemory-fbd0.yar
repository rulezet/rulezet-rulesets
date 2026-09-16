rule TTP_XOR_WriteProcessMemory_fbd0 {
  strings:
    $key_fbd0 = { ac a2 [2] 9e 80 [2] 98 b5 [2] b6 b5 [2] 89 a9 }

  condition:
    any of them
}