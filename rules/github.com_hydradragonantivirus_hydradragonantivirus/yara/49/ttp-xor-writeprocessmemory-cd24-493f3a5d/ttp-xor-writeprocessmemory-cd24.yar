rule TTP_XOR_WriteProcessMemory_cd24 {
  strings:
    $key_cd24 = { 9a 56 [2] a8 74 [2] ae 41 [2] 80 41 [2] bf 5d }

  condition:
    any of them
}