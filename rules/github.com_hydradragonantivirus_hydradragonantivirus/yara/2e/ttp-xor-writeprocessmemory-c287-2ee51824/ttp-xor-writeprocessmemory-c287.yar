rule TTP_XOR_WriteProcessMemory_c287 {
  strings:
    $key_c287 = { 95 f5 [2] a7 d7 [2] a1 e2 [2] 8f e2 [2] b0 fe }

  condition:
    any of them
}