rule TTP_XOR_WriteProcessMemory_c323 {
  strings:
    $key_c323 = { 94 51 [2] a6 73 [2] a0 46 [2] 8e 46 [2] b1 5a }

  condition:
    any of them
}