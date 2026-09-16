rule TTP_XOR_WriteProcessMemory_cd4e {
  strings:
    $key_cd4e = { 9a 3c [2] a8 1e [2] ae 2b [2] 80 2b [2] bf 37 }

  condition:
    any of them
}