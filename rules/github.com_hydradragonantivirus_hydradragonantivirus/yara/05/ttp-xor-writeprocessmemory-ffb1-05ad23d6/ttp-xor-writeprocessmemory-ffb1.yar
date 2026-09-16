rule TTP_XOR_WriteProcessMemory_ffb1 {
  strings:
    $key_ffb1 = { a8 c3 [2] 9a e1 [2] 9c d4 [2] b2 d4 [2] 8d c8 }

  condition:
    any of them
}