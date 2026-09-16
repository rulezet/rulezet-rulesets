rule TTP_XOR_WriteProcessMemory_cd7c {
  strings:
    $key_cd7c = { 9a 0e [2] a8 2c [2] ae 19 [2] 80 19 [2] bf 05 }

  condition:
    any of them
}