rule TTP_XOR_WriteProcessMemory_cd31 {
  strings:
    $key_cd31 = { 9a 43 [2] a8 61 [2] ae 54 [2] 80 54 [2] bf 48 }

  condition:
    any of them
}