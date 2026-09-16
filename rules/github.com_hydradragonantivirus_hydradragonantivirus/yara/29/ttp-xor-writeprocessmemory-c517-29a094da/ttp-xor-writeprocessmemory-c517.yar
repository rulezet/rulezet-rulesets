rule TTP_XOR_WriteProcessMemory_c517 {
  strings:
    $key_c517 = { 92 65 [2] a0 47 [2] a6 72 [2] 88 72 [2] b7 6e }

  condition:
    any of them
}