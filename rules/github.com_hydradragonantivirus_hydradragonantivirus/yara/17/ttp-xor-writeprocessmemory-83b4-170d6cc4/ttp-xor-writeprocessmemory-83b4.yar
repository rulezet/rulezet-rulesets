rule TTP_XOR_WriteProcessMemory_83b4 {
  strings:
    $key_83b4 = { d4 c6 [2] e6 e4 [2] e0 d1 [2] ce d1 [2] f1 cd }

  condition:
    any of them
}