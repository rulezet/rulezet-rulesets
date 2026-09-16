rule TTP_XOR_WriteProcessMemory_72b4 {
  strings:
    $key_72b4 = { 25 c6 [2] 17 e4 [2] 11 d1 [2] 3f d1 [2] 00 cd }

  condition:
    any of them
}