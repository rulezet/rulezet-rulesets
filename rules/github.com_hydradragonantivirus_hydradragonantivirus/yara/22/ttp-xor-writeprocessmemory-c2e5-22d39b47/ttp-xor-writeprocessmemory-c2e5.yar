rule TTP_XOR_WriteProcessMemory_c2e5 {
  strings:
    $key_c2e5 = { 95 97 [2] a7 b5 [2] a1 80 [2] 8f 80 [2] b0 9c }

  condition:
    any of them
}