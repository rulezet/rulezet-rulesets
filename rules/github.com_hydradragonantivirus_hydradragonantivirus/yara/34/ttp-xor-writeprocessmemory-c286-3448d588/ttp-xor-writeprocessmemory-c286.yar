rule TTP_XOR_WriteProcessMemory_c286 {
  strings:
    $key_c286 = { 95 f4 [2] a7 d6 [2] a1 e3 [2] 8f e3 [2] b0 ff }

  condition:
    any of them
}