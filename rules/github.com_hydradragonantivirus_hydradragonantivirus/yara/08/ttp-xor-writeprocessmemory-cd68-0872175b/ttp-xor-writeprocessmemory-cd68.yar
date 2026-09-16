rule TTP_XOR_WriteProcessMemory_cd68 {
  strings:
    $key_cd68 = { 9a 1a [2] a8 38 [2] ae 0d [2] 80 0d [2] bf 11 }

  condition:
    any of them
}