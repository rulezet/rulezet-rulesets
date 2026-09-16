rule TTP_XOR_WriteProcessMemory_c626 {
  strings:
    $key_c626 = { 91 54 [2] a3 76 [2] a5 43 [2] 8b 43 [2] b4 5f }

  condition:
    any of them
}