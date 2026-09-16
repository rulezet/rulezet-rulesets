rule TTP_XOR_WriteProcessMemory_2397 {
  strings:
    $key_2397 = { 74 e5 [2] 46 c7 [2] 40 f2 [2] 6e f2 [2] 51 ee }

  condition:
    any of them
}