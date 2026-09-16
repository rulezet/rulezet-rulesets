rule TTP_XOR_WriteProcessMemory_c746 {
  strings:
    $key_c746 = { 90 34 [2] a2 16 [2] a4 23 [2] 8a 23 [2] b5 3f }

  condition:
    any of them
}