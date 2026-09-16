rule TTP_XOR_WriteProcessMemory_cd0e {
  strings:
    $key_cd0e = { 9a 7c [2] a8 5e [2] ae 6b [2] 80 6b [2] bf 77 }

  condition:
    any of them
}