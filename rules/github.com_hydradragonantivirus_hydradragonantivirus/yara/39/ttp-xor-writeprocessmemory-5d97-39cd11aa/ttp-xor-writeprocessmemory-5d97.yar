rule TTP_XOR_WriteProcessMemory_5d97 {
  strings:
    $key_5d97 = { 0a e5 [2] 38 c7 [2] 3e f2 [2] 10 f2 [2] 2f ee }

  condition:
    any of them
}