rule TTP_XOR_WriteProcessMemory_cd3d {
  strings:
    $key_cd3d = { 9a 4f [2] a8 6d [2] ae 58 [2] 80 58 [2] bf 44 }

  condition:
    any of them
}