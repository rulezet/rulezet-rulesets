rule TTP_XOR_WriteProcessMemory_cd06 {
  strings:
    $key_cd06 = { 9a 74 [2] a8 56 [2] ae 63 [2] 80 63 [2] bf 7f }

  condition:
    any of them
}