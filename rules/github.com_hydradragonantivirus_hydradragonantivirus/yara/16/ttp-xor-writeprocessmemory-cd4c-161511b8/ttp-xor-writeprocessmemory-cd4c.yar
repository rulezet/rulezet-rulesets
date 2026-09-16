rule TTP_XOR_WriteProcessMemory_cd4c {
  strings:
    $key_cd4c = { 9a 3e [2] a8 1c [2] ae 29 [2] 80 29 [2] bf 35 }

  condition:
    any of them
}