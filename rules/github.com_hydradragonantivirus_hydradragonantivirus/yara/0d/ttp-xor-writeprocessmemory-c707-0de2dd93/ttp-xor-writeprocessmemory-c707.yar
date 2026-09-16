rule TTP_XOR_WriteProcessMemory_c707 {
  strings:
    $key_c707 = { 90 75 [2] a2 57 [2] a4 62 [2] 8a 62 [2] b5 7e }

  condition:
    any of them
}