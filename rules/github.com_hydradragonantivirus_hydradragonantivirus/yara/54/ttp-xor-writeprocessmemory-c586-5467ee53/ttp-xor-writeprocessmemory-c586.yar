rule TTP_XOR_WriteProcessMemory_c586 {
  strings:
    $key_c586 = { 92 f4 [2] a0 d6 [2] a6 e3 [2] 88 e3 [2] b7 ff }

  condition:
    any of them
}