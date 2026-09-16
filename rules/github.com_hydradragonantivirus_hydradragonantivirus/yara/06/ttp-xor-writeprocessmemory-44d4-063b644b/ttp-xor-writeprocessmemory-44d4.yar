rule TTP_XOR_WriteProcessMemory_44d4 {
  strings:
    $key_44d4 = { 13 a6 [2] 21 84 [2] 27 b1 [2] 09 b1 [2] 36 ad }

  condition:
    any of them
}