rule TTP_XOR_WriteProcessMemory_cd30 {
  strings:
    $key_cd30 = { 9a 42 [2] a8 60 [2] ae 55 [2] 80 55 [2] bf 49 }

  condition:
    any of them
}