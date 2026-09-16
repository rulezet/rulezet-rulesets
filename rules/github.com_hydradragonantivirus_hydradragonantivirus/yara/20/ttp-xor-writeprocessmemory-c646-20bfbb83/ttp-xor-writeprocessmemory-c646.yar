rule TTP_XOR_WriteProcessMemory_c646 {
  strings:
    $key_c646 = { 91 34 [2] a3 16 [2] a5 23 [2] 8b 23 [2] b4 3f }

  condition:
    any of them
}