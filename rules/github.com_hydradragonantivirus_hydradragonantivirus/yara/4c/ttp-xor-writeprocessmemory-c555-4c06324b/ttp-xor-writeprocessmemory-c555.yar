rule TTP_XOR_WriteProcessMemory_c555 {
  strings:
    $key_c555 = { 92 27 [2] a0 05 [2] a6 30 [2] 88 30 [2] b7 2c }

  condition:
    any of them
}