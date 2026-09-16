rule TTP_XOR_WriteProcessMemory_34b4 {
  strings:
    $key_34b4 = { 63 c6 [2] 51 e4 [2] 57 d1 [2] 79 d1 [2] 46 cd }

  condition:
    any of them
}