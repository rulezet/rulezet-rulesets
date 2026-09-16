rule TTP_XOR_WriteProcessMemory_35b4 {
  strings:
    $key_35b4 = { 62 c6 [2] 50 e4 [2] 56 d1 [2] 78 d1 [2] 47 cd }

  condition:
    any of them
}