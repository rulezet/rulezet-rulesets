rule TTP_XOR_WriteProcessMemory_cd54 {
  strings:
    $key_cd54 = { 9a 26 [2] a8 04 [2] ae 31 [2] 80 31 [2] bf 2d }

  condition:
    any of them
}