rule TTP_XOR_WriteProcessMemory_cd61 {
  strings:
    $key_cd61 = { 9a 13 [2] a8 31 [2] ae 04 [2] 80 04 [2] bf 18 }

  condition:
    any of them
}