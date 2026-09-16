rule TTP_XOR_WriteProcessMemory_cd58 {
  strings:
    $key_cd58 = { 9a 2a [2] a8 08 [2] ae 3d [2] 80 3d [2] bf 21 }

  condition:
    any of them
}