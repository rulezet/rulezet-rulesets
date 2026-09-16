rule TTP_XOR_WriteProcessMemory_cd42 {
  strings:
    $key_cd42 = { 9a 30 [2] a8 12 [2] ae 27 [2] 80 27 [2] bf 3b }

  condition:
    any of them
}