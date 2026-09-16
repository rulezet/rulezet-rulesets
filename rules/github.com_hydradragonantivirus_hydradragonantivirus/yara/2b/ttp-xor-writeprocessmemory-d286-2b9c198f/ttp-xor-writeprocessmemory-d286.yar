rule TTP_XOR_WriteProcessMemory_d286 {
  strings:
    $key_d286 = { 85 f4 [2] b7 d6 [2] b1 e3 [2] 9f e3 [2] a0 ff }

  condition:
    any of them
}