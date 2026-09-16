rule TTP_XOR_WriteProcessMemory_cd62 {
  strings:
    $key_cd62 = { 9a 10 [2] a8 32 [2] ae 07 [2] 80 07 [2] bf 1b }

  condition:
    any of them
}