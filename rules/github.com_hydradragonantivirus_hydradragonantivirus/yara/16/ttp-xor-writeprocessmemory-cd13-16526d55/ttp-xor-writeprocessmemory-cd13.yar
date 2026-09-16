rule TTP_XOR_WriteProcessMemory_cd13 {
  strings:
    $key_cd13 = { 9a 61 [2] a8 43 [2] ae 76 [2] 80 76 [2] bf 6a }

  condition:
    any of them
}