rule TTP_XOR_WriteProcessMemory_cdf6 {
  strings:
    $key_cdf6 = { 9a 84 [2] a8 a6 [2] ae 93 [2] 80 93 [2] bf 8f }

  condition:
    any of them
}