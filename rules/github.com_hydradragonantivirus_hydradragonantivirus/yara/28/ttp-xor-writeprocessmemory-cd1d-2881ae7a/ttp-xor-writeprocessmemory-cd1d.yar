rule TTP_XOR_WriteProcessMemory_cd1d {
  strings:
    $key_cd1d = { 9a 6f [2] a8 4d [2] ae 78 [2] 80 78 [2] bf 64 }

  condition:
    any of them
}