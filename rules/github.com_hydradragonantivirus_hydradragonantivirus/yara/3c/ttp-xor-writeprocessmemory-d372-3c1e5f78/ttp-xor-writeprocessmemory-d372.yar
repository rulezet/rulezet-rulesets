rule TTP_XOR_WriteProcessMemory_d372 {
  strings:
    $key_d372 = { 84 00 [2] b6 22 [2] b0 17 [2] 9e 17 [2] a1 0b }

  condition:
    any of them
}