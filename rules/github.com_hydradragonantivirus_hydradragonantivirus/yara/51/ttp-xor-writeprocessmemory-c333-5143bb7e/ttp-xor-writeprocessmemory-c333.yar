rule TTP_XOR_WriteProcessMemory_c333 {
  strings:
    $key_c333 = { 94 41 [2] a6 63 [2] a0 56 [2] 8e 56 [2] b1 4a }

  condition:
    any of them
}