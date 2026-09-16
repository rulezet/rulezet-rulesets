rule TTP_XOR_WriteProcessMemory_cd49 {
  strings:
    $key_cd49 = { 9a 3b [2] a8 19 [2] ae 2c [2] 80 2c [2] bf 30 }

  condition:
    any of them
}