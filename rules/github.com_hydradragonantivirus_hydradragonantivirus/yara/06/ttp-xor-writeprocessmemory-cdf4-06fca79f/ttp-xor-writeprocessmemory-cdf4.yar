rule TTP_XOR_WriteProcessMemory_cdf4 {
  strings:
    $key_cdf4 = { 9a 86 [2] a8 a4 [2] ae 91 [2] 80 91 [2] bf 8d }

  condition:
    any of them
}