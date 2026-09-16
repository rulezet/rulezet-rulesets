rule TTP_XOR_WriteProcessMemory_5497 {
  strings:
    $key_5497 = { 03 e5 [2] 31 c7 [2] 37 f2 [2] 19 f2 [2] 26 ee }

  condition:
    any of them
}