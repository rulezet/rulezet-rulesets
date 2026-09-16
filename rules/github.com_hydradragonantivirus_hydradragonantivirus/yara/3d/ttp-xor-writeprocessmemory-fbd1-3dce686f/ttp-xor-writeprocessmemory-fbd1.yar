rule TTP_XOR_WriteProcessMemory_fbd1 {
  strings:
    $key_fbd1 = { ac a3 [2] 9e 81 [2] 98 b4 [2] b6 b4 [2] 89 a8 }

  condition:
    any of them
}