rule TTP_XOR_WriteProcessMemory_cd53 {
  strings:
    $key_cd53 = { 9a 21 [2] a8 03 [2] ae 36 [2] 80 36 [2] bf 2a }

  condition:
    any of them
}