rule TTP_XOR_WriteProcessMemory_e2b4 {
  strings:
    $key_e2b4 = { b5 c6 [2] 87 e4 [2] 81 d1 [2] af d1 [2] 90 cd }

  condition:
    any of them
}