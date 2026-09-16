rule TTP_XOR_WriteProcessMemory_cdfb {
  strings:
    $key_cdfb = { 9a 89 [2] a8 ab [2] ae 9e [2] 80 9e [2] bf 82 }

  condition:
    any of them
}