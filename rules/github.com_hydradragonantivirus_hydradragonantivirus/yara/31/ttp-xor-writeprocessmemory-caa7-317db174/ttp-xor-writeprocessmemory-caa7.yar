rule TTP_XOR_WriteProcessMemory_caa7 {
  strings:
    $key_caa7 = { 9d d5 [2] af f7 [2] a9 c2 [2] 87 c2 [2] b8 de }

  condition:
    any of them
}