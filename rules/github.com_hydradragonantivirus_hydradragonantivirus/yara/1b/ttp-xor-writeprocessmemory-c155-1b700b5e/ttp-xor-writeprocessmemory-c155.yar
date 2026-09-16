rule TTP_XOR_WriteProcessMemory_c155 {
  strings:
    $key_c155 = { 96 27 [2] a4 05 [2] a2 30 [2] 8c 30 [2] b3 2c }

  condition:
    any of them
}