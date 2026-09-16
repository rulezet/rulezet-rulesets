rule TTP_XOR_WriteProcessMemory_cd5d {
  strings:
    $key_cd5d = { 9a 2f [2] a8 0d [2] ae 38 [2] 80 38 [2] bf 24 }

  condition:
    any of them
}