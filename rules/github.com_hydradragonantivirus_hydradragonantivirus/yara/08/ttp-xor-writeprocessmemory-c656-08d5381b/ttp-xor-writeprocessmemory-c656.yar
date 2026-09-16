rule TTP_XOR_WriteProcessMemory_c656 {
  strings:
    $key_c656 = { 91 24 [2] a3 06 [2] a5 33 [2] 8b 33 [2] b4 2f }

  condition:
    any of them
}