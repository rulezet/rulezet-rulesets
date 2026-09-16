rule TTP_XOR_WriteProcessMemory_c6f2 {
  strings:
    $key_c6f2 = { 91 80 [2] a3 a2 [2] a5 97 [2] 8b 97 [2] b4 8b }

  condition:
    any of them
}