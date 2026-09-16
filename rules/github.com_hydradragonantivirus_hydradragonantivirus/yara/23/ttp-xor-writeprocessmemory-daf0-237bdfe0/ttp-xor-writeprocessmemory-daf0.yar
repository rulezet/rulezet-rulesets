rule TTP_XOR_WriteProcessMemory_daf0 {
  strings:
    $key_daf0 = { 8d 82 [2] bf a0 [2] b9 95 [2] 97 95 [2] a8 89 }

  condition:
    any of them
}