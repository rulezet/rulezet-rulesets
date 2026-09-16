rule TTP_XOR_WriteProcessMemory_c0e2 {
  strings:
    $key_c0e2 = { 97 90 [2] a5 b2 [2] a3 87 [2] 8d 87 [2] b2 9b }

  condition:
    any of them
}