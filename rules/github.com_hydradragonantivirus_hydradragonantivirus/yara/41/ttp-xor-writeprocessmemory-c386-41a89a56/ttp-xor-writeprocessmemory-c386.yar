rule TTP_XOR_WriteProcessMemory_c386 {
  strings:
    $key_c386 = { 94 f4 [2] a6 d6 [2] a0 e3 [2] 8e e3 [2] b1 ff }

  condition:
    any of them
}