rule TTP_XOR_WriteProcessMemory_cd92 {
  strings:
    $key_cd92 = { 9a e0 [2] a8 c2 [2] ae f7 [2] 80 f7 [2] bf eb }

  condition:
    any of them
}