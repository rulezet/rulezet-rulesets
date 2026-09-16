rule TTP_XOR_WriteProcessMemory_2097 {
  strings:
    $key_2097 = { 77 e5 [2] 45 c7 [2] 43 f2 [2] 6d f2 [2] 52 ee }

  condition:
    any of them
}