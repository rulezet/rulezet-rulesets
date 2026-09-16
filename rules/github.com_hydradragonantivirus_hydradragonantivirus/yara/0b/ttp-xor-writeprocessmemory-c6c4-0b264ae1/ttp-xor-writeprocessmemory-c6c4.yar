rule TTP_XOR_WriteProcessMemory_c6c4 {
  strings:
    $key_c6c4 = { 91 b6 [2] a3 94 [2] a5 a1 [2] 8b a1 [2] b4 bd }

  condition:
    any of them
}