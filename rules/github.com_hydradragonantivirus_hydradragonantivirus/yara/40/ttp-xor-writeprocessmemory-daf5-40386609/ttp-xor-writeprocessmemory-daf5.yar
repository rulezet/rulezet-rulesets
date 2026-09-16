rule TTP_XOR_WriteProcessMemory_daf5 {
  strings:
    $key_daf5 = { 8d 87 [2] bf a5 [2] b9 90 [2] 97 90 [2] a8 8c }

  condition:
    any of them
}