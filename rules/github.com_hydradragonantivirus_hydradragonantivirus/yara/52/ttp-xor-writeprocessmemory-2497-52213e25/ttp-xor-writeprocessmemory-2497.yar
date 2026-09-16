rule TTP_XOR_WriteProcessMemory_2497 {
  strings:
    $key_2497 = { 73 e5 [2] 41 c7 [2] 47 f2 [2] 69 f2 [2] 56 ee }

  condition:
    any of them
}