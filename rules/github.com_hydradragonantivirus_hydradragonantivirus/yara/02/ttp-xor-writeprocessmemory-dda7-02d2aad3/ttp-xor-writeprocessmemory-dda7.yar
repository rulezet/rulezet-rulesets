rule TTP_XOR_WriteProcessMemory_dda7 {
  strings:
    $key_dda7 = { 8a d5 [2] b8 f7 [2] be c2 [2] 90 c2 [2] af de }

  condition:
    any of them
}