rule TTP_XOR_WriteProcessMemory_c32b {
  strings:
    $key_c32b = { 94 59 [2] a6 7b [2] a0 4e [2] 8e 4e [2] b1 52 }

  condition:
    any of them
}