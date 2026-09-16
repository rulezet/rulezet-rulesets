rule TTP_XOR_WriteProcessMemory_caa9 {
  strings:
    $key_caa9 = { 9d db [2] af f9 [2] a9 cc [2] 87 cc [2] b8 d0 }

  condition:
    any of them
}