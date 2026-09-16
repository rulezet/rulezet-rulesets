rule TTP_XOR_WriteProcessMemory_cd2b {
  strings:
    $key_cd2b = { 9a 59 [2] a8 7b [2] ae 4e [2] 80 4e [2] bf 52 }

  condition:
    any of them
}