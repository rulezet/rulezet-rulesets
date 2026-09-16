rule TTP_XOR_WriteProcessMemory_dda4 {
  strings:
    $key_dda4 = { 8a d6 [2] b8 f4 [2] be c1 [2] 90 c1 [2] af dd }

  condition:
    any of them
}