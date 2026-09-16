rule TTP_XOR_WriteProcessMemory_c686 {
  strings:
    $key_c686 = { 91 f4 [2] a3 d6 [2] a5 e3 [2] 8b e3 [2] b4 ff }

  condition:
    any of them
}