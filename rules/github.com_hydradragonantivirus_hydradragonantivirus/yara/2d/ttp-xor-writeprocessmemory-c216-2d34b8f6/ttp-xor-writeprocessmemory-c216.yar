rule TTP_XOR_WriteProcessMemory_c216 {
  strings:
    $key_c216 = { 95 64 [2] a7 46 [2] a1 73 [2] 8f 73 [2] b0 6f }

  condition:
    any of them
}