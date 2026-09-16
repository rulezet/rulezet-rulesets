rule TTP_XOR_WriteProcessMemory_caa2 {
  strings:
    $key_caa2 = { 9d d0 [2] af f2 [2] a9 c7 [2] 87 c7 [2] b8 db }

  condition:
    any of them
}