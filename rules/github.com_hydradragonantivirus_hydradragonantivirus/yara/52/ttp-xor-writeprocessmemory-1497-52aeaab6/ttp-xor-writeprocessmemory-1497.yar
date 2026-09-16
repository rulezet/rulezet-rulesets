rule TTP_XOR_WriteProcessMemory_1497 {
  strings:
    $key_1497 = { 43 e5 [2] 71 c7 [2] 77 f2 [2] 59 f2 [2] 66 ee }

  condition:
    any of them
}