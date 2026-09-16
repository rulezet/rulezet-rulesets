rule TTP_XOR_WriteProcessMemory_c363 {
  strings:
    $key_c363 = { 94 11 [2] a6 33 [2] a0 06 [2] 8e 06 [2] b1 1a }

  condition:
    any of them
}