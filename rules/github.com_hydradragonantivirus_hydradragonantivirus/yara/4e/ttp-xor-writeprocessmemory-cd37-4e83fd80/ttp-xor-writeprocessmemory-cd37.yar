rule TTP_XOR_WriteProcessMemory_cd37 {
  strings:
    $key_cd37 = { 9a 45 [2] a8 67 [2] ae 52 [2] 80 52 [2] bf 4e }

  condition:
    any of them
}