rule TTP_XOR_WriteProcessMemory_37c1 {
  strings:
    $key_37c1 = { 60 b3 [2] 52 91 [2] 54 a4 [2] 7a a4 [2] 45 b8 }

  condition:
    any of them
}