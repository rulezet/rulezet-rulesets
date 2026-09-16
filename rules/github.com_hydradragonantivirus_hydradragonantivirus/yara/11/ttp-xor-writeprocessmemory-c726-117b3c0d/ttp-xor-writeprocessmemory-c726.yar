rule TTP_XOR_WriteProcessMemory_c726 {
  strings:
    $key_c726 = { 90 54 [2] a2 76 [2] a4 43 [2] 8a 43 [2] b5 5f }

  condition:
    any of them
}