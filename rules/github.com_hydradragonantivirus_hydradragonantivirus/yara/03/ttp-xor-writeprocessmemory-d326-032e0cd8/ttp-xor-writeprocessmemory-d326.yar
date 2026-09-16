rule TTP_XOR_WriteProcessMemory_d326 {
  strings:
    $key_d326 = { 84 54 [2] b6 76 [2] b0 43 [2] 9e 43 [2] a1 5f }

  condition:
    any of them
}