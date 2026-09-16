rule TTP_XOR_WriteProcessMemory_2797 {
  strings:
    $key_2797 = { 70 e5 [2] 42 c7 [2] 44 f2 [2] 6a f2 [2] 55 ee }

  condition:
    any of them
}