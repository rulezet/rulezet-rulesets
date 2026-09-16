rule TTP_XOR_WriteProcessMemory_55b4 {
  strings:
    $key_55b4 = { 02 c6 [2] 30 e4 [2] 36 d1 [2] 18 d1 [2] 27 cd }

  condition:
    any of them
}