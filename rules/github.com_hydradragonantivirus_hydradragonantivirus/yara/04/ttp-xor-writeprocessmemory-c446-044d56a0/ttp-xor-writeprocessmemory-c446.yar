rule TTP_XOR_WriteProcessMemory_c446 {
  strings:
    $key_c446 = { 93 34 [2] a1 16 [2] a7 23 [2] 89 23 [2] b6 3f }

  condition:
    any of them
}