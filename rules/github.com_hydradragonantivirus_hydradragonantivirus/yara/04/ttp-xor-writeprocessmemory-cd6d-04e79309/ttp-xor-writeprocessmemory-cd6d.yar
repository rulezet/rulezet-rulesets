rule TTP_XOR_WriteProcessMemory_cd6d {
  strings:
    $key_cd6d = { 9a 1f [2] a8 3d [2] ae 08 [2] 80 08 [2] bf 14 }

  condition:
    any of them
}