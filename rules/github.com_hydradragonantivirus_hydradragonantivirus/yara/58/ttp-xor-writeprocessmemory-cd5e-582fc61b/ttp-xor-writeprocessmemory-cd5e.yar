rule TTP_XOR_WriteProcessMemory_cd5e {
  strings:
    $key_cd5e = { 9a 2c [2] a8 0e [2] ae 3b [2] 80 3b [2] bf 27 }

  condition:
    any of them
}