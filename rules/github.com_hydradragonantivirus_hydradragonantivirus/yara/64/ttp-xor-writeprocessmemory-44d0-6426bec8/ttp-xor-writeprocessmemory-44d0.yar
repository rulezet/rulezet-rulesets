rule TTP_XOR_WriteProcessMemory_44d0 {
  strings:
    $key_44d0 = { 13 a2 [2] 21 80 [2] 27 b5 [2] 09 b5 [2] 36 a9 }

  condition:
    any of them
}