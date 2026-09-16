rule TTP_XOR_WriteProcessMemory_c53c {
  strings:
    $key_c53c = { 92 4e [2] a0 6c [2] a6 59 [2] 88 59 [2] b7 45 }

  condition:
    any of them
}