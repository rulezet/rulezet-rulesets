rule TTP_XOR_WriteProcessMemory_fca3 {
  strings:
    $key_fca3 = { ab d1 [2] 99 f3 [2] 9f c6 [2] b1 c6 [2] 8e da }

  condition:
    any of them
}