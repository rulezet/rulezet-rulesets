rule TTP_XOR_WriteProcessMemory_cd60 {
  strings:
    $key_cd60 = { 9a 12 [2] a8 30 [2] ae 05 [2] 80 05 [2] bf 19 }

  condition:
    any of them
}