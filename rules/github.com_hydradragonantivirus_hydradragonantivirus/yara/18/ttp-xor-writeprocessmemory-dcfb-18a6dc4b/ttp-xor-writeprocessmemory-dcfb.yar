rule TTP_XOR_WriteProcessMemory_dcfb {
  strings:
    $key_dcfb = { 8b 89 [2] b9 ab [2] bf 9e [2] 91 9e [2] ae 82 }

  condition:
    any of them
}