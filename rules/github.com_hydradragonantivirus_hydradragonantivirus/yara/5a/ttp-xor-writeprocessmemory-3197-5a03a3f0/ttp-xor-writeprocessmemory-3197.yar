rule TTP_XOR_WriteProcessMemory_3197 {
  strings:
    $key_3197 = { 66 e5 [2] 54 c7 [2] 52 f2 [2] 7c f2 [2] 43 ee }

  condition:
    any of them
}