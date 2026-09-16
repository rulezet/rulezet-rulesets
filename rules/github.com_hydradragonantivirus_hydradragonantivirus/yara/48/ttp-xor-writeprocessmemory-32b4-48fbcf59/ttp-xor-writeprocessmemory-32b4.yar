rule TTP_XOR_WriteProcessMemory_32b4 {
  strings:
    $key_32b4 = { 65 c6 [2] 57 e4 [2] 51 d1 [2] 7f d1 [2] 40 cd }

  condition:
    any of them
}