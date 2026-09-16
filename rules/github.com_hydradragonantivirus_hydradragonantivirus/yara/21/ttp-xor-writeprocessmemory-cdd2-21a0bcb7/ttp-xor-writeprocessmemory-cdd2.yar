rule TTP_XOR_WriteProcessMemory_cdd2 {
  strings:
    $key_cdd2 = { 9a a0 [2] a8 82 [2] ae b7 [2] 80 b7 [2] bf ab }

  condition:
    any of them
}