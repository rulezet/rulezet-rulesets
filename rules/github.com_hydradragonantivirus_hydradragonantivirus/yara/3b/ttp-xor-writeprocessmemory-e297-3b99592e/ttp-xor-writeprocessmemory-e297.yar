rule TTP_XOR_WriteProcessMemory_e297 {
  strings:
    $key_e297 = { b5 e5 [2] 87 c7 [2] 81 f2 [2] af f2 [2] 90 ee }

  condition:
    any of them
}