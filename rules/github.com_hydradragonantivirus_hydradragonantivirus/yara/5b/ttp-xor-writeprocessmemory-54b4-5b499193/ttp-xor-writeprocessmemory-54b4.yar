rule TTP_XOR_WriteProcessMemory_54b4 {
  strings:
    $key_54b4 = { 03 c6 [2] 31 e4 [2] 37 d1 [2] 19 d1 [2] 26 cd }

  condition:
    any of them
}