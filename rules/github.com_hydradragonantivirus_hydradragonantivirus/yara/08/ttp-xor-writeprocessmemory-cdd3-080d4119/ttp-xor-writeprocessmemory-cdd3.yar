rule TTP_XOR_WriteProcessMemory_cdd3 {
  strings:
    $key_cdd3 = { 9a a1 [2] a8 83 [2] ae b6 [2] 80 b6 [2] bf aa }

  condition:
    any of them
}