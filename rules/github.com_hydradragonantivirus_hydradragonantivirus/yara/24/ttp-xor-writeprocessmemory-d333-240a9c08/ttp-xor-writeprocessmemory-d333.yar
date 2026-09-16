rule TTP_XOR_WriteProcessMemory_d333 {
  strings:
    $key_d333 = { 84 41 [2] b6 63 [2] b0 56 [2] 9e 56 [2] a1 4a }

  condition:
    any of them
}