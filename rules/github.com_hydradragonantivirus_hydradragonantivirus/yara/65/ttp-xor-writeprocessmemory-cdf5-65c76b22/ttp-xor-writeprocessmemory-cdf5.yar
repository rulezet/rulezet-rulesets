rule TTP_XOR_WriteProcessMemory_cdf5 {
  strings:
    $key_cdf5 = { 9a 87 [2] a8 a5 [2] ae 90 [2] 80 90 [2] bf 8c }

  condition:
    any of them
}