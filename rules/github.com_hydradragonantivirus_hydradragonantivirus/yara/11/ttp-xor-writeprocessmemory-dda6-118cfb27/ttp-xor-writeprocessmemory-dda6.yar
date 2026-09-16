rule TTP_XOR_WriteProcessMemory_dda6 {
  strings:
    $key_dda6 = { 8a d4 [2] b8 f6 [2] be c3 [2] 90 c3 [2] af df }

  condition:
    any of them
}