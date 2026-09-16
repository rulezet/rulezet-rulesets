rule TTP_XOR_WriteProcessMemory_cd3b {
  strings:
    $key_cd3b = { 9a 49 [2] a8 6b [2] ae 5e [2] 80 5e [2] bf 42 }

  condition:
    any of them
}