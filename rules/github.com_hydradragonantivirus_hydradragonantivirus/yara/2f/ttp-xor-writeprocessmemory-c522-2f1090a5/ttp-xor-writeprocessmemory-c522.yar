rule TTP_XOR_WriteProcessMemory_c522 {
  strings:
    $key_c522 = { 92 50 [2] a0 72 [2] a6 47 [2] 88 47 [2] b7 5b }

  condition:
    any of them
}