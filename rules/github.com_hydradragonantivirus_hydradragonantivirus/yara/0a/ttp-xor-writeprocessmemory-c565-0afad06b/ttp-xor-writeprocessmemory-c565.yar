rule TTP_XOR_WriteProcessMemory_c565 {
  strings:
    $key_c565 = { 92 17 [2] a0 35 [2] a6 00 [2] 88 00 [2] b7 1c }

  condition:
    any of them
}