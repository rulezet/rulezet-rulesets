rule TTP_XOR_WriteProcessMemory_cd94 {
  strings:
    $key_cd94 = { 9a e6 [2] a8 c4 [2] ae f1 [2] 80 f1 [2] bf ed }

  condition:
    any of them
}