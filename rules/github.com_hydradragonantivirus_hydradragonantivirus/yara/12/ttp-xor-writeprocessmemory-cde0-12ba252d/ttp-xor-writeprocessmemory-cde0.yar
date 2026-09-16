rule TTP_XOR_WriteProcessMemory_cde0 {
  strings:
    $key_cde0 = { 9a 92 [2] a8 b0 [2] ae 85 [2] 80 85 [2] bf 99 }

  condition:
    any of them
}