rule TTP_XOR_WriteProcessMemory_fdfb {
  strings:
    $key_fdfb = { aa 89 [2] 98 ab [2] 9e 9e [2] b0 9e [2] 8f 82 }

  condition:
    any of them
}