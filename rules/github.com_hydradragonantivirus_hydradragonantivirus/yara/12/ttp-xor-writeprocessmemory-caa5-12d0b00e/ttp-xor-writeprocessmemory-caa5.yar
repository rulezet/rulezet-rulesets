rule TTP_XOR_WriteProcessMemory_caa5 {
  strings:
    $key_caa5 = { 9d d7 [2] af f5 [2] a9 c0 [2] 87 c0 [2] b8 dc }

  condition:
    any of them
}