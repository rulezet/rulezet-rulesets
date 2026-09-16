rule TTP_XOR_WriteProcessMemory_d7e2 {
  strings:
    $key_d7e2 = { 80 90 [2] b2 b2 [2] b4 87 [2] 9a 87 [2] a5 9b }

  condition:
    any of them
}