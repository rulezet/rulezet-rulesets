rule TTP_XOR_WriteProcessMemory_31b4 {
  strings:
    $key_31b4 = { 66 c6 [2] 54 e4 [2] 52 d1 [2] 7c d1 [2] 43 cd }

  condition:
    any of them
}