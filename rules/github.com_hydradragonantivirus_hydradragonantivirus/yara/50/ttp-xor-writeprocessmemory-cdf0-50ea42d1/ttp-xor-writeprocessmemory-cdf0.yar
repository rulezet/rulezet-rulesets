rule TTP_XOR_WriteProcessMemory_cdf0 {
  strings:
    $key_cdf0 = { 9a 82 [2] a8 a0 [2] ae 95 [2] 80 95 [2] bf 89 }

  condition:
    any of them
}