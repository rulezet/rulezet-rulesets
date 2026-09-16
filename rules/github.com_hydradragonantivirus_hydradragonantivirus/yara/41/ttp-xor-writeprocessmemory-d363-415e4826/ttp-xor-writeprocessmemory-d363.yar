rule TTP_XOR_WriteProcessMemory_d363 {
  strings:
    $key_d363 = { 84 11 [2] b6 33 [2] b0 06 [2] 9e 06 [2] a1 1a }

  condition:
    any of them
}