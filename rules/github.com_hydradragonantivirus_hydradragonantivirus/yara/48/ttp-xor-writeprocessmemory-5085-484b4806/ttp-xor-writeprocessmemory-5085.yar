rule TTP_XOR_WriteProcessMemory_5085 {
  strings:
    $key_5085 = { 07 f7 [2] 35 d5 [2] 33 e0 [2] 1d e0 [2] 22 fc }

  condition:
    any of them
}