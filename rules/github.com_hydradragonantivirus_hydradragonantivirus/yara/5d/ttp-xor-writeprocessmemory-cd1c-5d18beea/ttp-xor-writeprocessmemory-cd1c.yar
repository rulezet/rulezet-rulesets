rule TTP_XOR_WriteProcessMemory_cd1c {
  strings:
    $key_cd1c = { 9a 6e [2] a8 4c [2] ae 79 [2] 80 79 [2] bf 65 }

  condition:
    any of them
}