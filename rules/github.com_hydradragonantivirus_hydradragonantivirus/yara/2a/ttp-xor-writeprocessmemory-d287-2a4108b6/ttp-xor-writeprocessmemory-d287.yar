rule TTP_XOR_WriteProcessMemory_d287 {
  strings:
    $key_d287 = { 85 f5 [2] b7 d7 [2] b1 e2 [2] 9f e2 [2] a0 fe }

  condition:
    any of them
}