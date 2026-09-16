rule TTP_XOR_WriteProcessMemory_cd91 {
  strings:
    $key_cd91 = { 9a e3 [2] a8 c1 [2] ae f4 [2] 80 f4 [2] bf e8 }

  condition:
    any of them
}