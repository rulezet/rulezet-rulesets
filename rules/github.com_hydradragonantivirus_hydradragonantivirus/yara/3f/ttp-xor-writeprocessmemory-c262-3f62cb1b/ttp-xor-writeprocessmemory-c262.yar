rule TTP_XOR_WriteProcessMemory_c262 {
  strings:
    $key_c262 = { 95 10 [2] a7 32 [2] a1 07 [2] 8f 07 [2] b0 1b }

  condition:
    any of them
}