rule TTP_XOR_WriteProcessMemory_c6f3 {
  strings:
    $key_c6f3 = { 91 81 [2] a3 a3 [2] a5 96 [2] 8b 96 [2] b4 8a }

  condition:
    any of them
}