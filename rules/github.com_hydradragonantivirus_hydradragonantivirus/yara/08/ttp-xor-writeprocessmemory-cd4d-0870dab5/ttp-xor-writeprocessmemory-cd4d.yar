rule TTP_XOR_WriteProcessMemory_cd4d {
  strings:
    $key_cd4d = { 9a 3f [2] a8 1d [2] ae 28 [2] 80 28 [2] bf 34 }

  condition:
    any of them
}