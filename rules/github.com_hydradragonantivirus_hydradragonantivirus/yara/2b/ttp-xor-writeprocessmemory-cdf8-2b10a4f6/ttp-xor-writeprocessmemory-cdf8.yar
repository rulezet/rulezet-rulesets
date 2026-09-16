rule TTP_XOR_WriteProcessMemory_cdf8 {
  strings:
    $key_cdf8 = { 9a 8a [2] a8 a8 [2] ae 9d [2] 80 9d [2] bf 81 }

  condition:
    any of them
}