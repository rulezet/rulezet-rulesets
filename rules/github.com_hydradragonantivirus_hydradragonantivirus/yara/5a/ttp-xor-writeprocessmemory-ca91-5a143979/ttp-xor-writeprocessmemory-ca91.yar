rule TTP_XOR_WriteProcessMemory_ca91 {
  strings:
    $key_ca91 = { 9d e3 [2] af c1 [2] a9 f4 [2] 87 f4 [2] b8 e8 }

  condition:
    any of them
}