rule TTP_XOR_WriteProcessMemory_c2c8 {
  strings:
    $key_c2c8 = { 95 ba [2] a7 98 [2] a1 ad [2] 8f ad [2] b0 b1 }

  condition:
    any of them
}