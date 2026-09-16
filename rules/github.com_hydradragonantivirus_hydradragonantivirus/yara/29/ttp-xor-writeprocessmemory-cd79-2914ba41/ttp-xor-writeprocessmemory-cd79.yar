rule TTP_XOR_WriteProcessMemory_cd79 {
  strings:
    $key_cd79 = { 9a 0b [2] a8 29 [2] ae 1c [2] 80 1c [2] bf 00 }

  condition:
    any of them
}