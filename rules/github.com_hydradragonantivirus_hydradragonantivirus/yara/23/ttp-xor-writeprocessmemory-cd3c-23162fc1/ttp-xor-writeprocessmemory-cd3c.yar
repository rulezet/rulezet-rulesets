rule TTP_XOR_WriteProcessMemory_cd3c {
  strings:
    $key_cd3c = { 9a 4e [2] a8 6c [2] ae 59 [2] 80 59 [2] bf 45 }

  condition:
    any of them
}