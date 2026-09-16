rule TTP_XOR_WriteProcessMemory_cd57 {
  strings:
    $key_cd57 = { 9a 25 [2] a8 07 [2] ae 32 [2] 80 32 [2] bf 2e }

  condition:
    any of them
}