rule TTP_XOR_WriteProcessMemory_cdd0 {
  strings:
    $key_cdd0 = { 9a a2 [2] a8 80 [2] ae b5 [2] 80 b5 [2] bf a9 }

  condition:
    any of them
}