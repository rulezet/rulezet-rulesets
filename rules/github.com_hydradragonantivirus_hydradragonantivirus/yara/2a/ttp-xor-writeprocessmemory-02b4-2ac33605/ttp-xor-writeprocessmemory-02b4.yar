rule TTP_XOR_WriteProcessMemory_02b4 {
  strings:
    $key_02b4 = { 55 c6 [2] 67 e4 [2] 61 d1 [2] 4f d1 [2] 70 cd }

  condition:
    any of them
}