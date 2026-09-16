rule TTP_XOR_WriteProcessMemory_fca6 {
  strings:
    $key_fca6 = { ab d4 [2] 99 f6 [2] 9f c3 [2] b1 c3 [2] 8e df }

  condition:
    any of them
}