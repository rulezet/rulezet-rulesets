rule TTP_XOR_WriteProcessMemory_c531 {
  strings:
    $key_c531 = { 92 43 [2] a0 61 [2] a6 54 [2] 88 54 [2] b7 48 }

  condition:
    any of them
}