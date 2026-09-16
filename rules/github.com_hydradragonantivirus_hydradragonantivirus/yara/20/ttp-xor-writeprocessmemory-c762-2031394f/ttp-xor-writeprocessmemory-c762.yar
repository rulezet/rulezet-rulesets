rule TTP_XOR_WriteProcessMemory_c762 {
  strings:
    $key_c762 = { 90 10 [2] a2 32 [2] a4 07 [2] 8a 07 [2] b5 1b }

  condition:
    any of them
}