rule TTP_XOR_WriteProcessMemory_cd75 {
  strings:
    $key_cd75 = { 9a 07 [2] a8 25 [2] ae 10 [2] 80 10 [2] bf 0c }

  condition:
    any of them
}