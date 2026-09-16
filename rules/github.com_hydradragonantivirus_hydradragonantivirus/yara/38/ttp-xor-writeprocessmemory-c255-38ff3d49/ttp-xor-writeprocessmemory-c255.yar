rule TTP_XOR_WriteProcessMemory_c255 {
  strings:
    $key_c255 = { 95 27 [2] a7 05 [2] a1 30 [2] 8f 30 [2] b0 2c }

  condition:
    any of them
}