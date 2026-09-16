rule TTP_XOR_WriteProcessMemory_f697 {
  strings:
    $key_f697 = { a1 e5 [2] 93 c7 [2] 95 f2 [2] bb f2 [2] 84 ee }

  condition:
    any of them
}