rule TTP_XOR_WriteProcessMemory_2197 {
  strings:
    $key_2197 = { 76 e5 [2] 44 c7 [2] 42 f2 [2] 6c f2 [2] 53 ee }

  condition:
    any of them
}