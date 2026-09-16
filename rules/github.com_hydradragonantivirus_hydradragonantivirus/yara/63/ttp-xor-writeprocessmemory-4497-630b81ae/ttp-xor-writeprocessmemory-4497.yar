rule TTP_XOR_WriteProcessMemory_4497 {
  strings:
    $key_4497 = { 13 e5 [2] 21 c7 [2] 27 f2 [2] 09 f2 [2] 36 ee }

  condition:
    any of them
}