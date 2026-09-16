rule TTP_XOR_WriteProcessMemory_dda0 {
  strings:
    $key_dda0 = { 8a d2 [2] b8 f0 [2] be c5 [2] 90 c5 [2] af d9 }

  condition:
    any of them
}