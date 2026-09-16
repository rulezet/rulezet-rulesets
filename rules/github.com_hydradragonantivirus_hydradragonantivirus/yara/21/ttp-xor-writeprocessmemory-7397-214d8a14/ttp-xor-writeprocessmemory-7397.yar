rule TTP_XOR_WriteProcessMemory_7397 {
  strings:
    $key_7397 = { 24 e5 [2] 16 c7 [2] 10 f2 [2] 3e f2 [2] 01 ee }

  condition:
    any of them
}