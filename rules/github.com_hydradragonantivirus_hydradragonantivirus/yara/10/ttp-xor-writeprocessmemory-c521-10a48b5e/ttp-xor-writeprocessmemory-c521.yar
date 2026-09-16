rule TTP_XOR_WriteProcessMemory_c521 {
  strings:
    $key_c521 = { 92 53 [2] a0 71 [2] a6 44 [2] 88 44 [2] b7 58 }

  condition:
    any of them
}