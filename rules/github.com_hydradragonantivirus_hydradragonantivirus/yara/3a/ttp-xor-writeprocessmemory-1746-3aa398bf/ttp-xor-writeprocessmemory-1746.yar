rule TTP_XOR_WriteProcessMemory_1746 {
  strings:
    $key_1746 = { 40 34 [2] 72 16 [2] 74 23 [2] 5a 23 [2] 65 3f }

  condition:
    any of them
}