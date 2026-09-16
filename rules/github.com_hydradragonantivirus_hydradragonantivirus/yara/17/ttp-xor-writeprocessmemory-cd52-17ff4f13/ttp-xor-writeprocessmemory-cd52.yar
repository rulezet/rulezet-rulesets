rule TTP_XOR_WriteProcessMemory_cd52 {
  strings:
    $key_cd52 = { 9a 20 [2] a8 02 [2] ae 37 [2] 80 37 [2] bf 2b }

  condition:
    any of them
}