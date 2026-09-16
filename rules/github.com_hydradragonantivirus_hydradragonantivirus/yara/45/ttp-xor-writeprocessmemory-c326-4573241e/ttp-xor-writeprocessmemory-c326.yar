rule TTP_XOR_WriteProcessMemory_c326 {
  strings:
    $key_c326 = { 94 54 [2] a6 76 [2] a0 43 [2] 8e 43 [2] b1 5f }

  condition:
    any of them
}