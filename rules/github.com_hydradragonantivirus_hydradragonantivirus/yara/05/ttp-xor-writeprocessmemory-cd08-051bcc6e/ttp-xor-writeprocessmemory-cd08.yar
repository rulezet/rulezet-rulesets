rule TTP_XOR_WriteProcessMemory_cd08 {
  strings:
    $key_cd08 = { 9a 7a [2] a8 58 [2] ae 6d [2] 80 6d [2] bf 71 }

  condition:
    any of them
}