rule TTP_XOR_WriteProcessMemory_d586 {
  strings:
    $key_d586 = { 82 f4 [2] b0 d6 [2] b6 e3 [2] 98 e3 [2] a7 ff }

  condition:
    any of them
}