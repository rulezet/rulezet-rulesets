rule TTP_XOR_WriteProcessMemory_7d97 {
  strings:
    $key_7d97 = { 2a e5 [2] 18 c7 [2] 1e f2 [2] 30 f2 [2] 0f ee }

  condition:
    any of them
}