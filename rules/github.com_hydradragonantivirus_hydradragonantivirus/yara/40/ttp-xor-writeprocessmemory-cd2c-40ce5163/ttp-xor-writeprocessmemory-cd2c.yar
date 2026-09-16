rule TTP_XOR_WriteProcessMemory_cd2c {
  strings:
    $key_cd2c = { 9a 5e [2] a8 7c [2] ae 49 [2] 80 49 [2] bf 55 }

  condition:
    any of them
}