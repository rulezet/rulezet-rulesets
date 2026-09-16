rule TTP_XOR_WriteProcessMemory_cd76 {
  strings:
    $key_cd76 = { 9a 04 [2] a8 26 [2] ae 13 [2] 80 13 [2] bf 0f }

  condition:
    any of them
}