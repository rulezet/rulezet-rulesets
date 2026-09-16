rule TTP_XOR_WriteProcessMemory_e7b4 {
  strings:
    $key_e7b4 = { b0 c6 [2] 82 e4 [2] 84 d1 [2] aa d1 [2] 95 cd }

  condition:
    any of them
}