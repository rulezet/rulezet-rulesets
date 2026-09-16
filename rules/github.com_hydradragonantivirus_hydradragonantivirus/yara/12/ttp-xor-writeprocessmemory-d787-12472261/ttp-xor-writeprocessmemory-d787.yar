rule TTP_XOR_WriteProcessMemory_d787 {
  strings:
    $key_d787 = { 80 f5 [2] b2 d7 [2] b4 e2 [2] 9a e2 [2] a5 fe }

  condition:
    any of them
}