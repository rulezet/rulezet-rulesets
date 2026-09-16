rule TTP_XOR_WriteProcessMemory_c6f7 {
  strings:
    $key_c6f7 = { 91 85 [2] a3 a7 [2] a5 92 [2] 8b 92 [2] b4 8e }

  condition:
    any of them
}