rule TTP_XOR_WriteProcessMemory_cd78 {
  strings:
    $key_cd78 = { 9a 0a [2] a8 28 [2] ae 1d [2] 80 1d [2] bf 01 }

  condition:
    any of them
}