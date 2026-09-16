rule TTP_XOR_WriteProcessMemory_cd1b {
  strings:
    $key_cd1b = { 9a 69 [2] a8 4b [2] ae 7e [2] 80 7e [2] bf 62 }

  condition:
    any of them
}