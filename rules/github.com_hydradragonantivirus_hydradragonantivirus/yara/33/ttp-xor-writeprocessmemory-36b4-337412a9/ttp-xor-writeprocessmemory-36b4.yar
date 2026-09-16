rule TTP_XOR_WriteProcessMemory_36b4 {
  strings:
    $key_36b4 = { 61 c6 [2] 53 e4 [2] 55 d1 [2] 7b d1 [2] 44 cd }

  condition:
    any of them
}