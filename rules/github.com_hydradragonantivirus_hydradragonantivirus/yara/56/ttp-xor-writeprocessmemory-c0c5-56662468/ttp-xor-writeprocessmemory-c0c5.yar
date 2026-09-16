rule TTP_XOR_WriteProcessMemory_c0c5 {
  strings:
    $key_c0c5 = { 97 b7 [2] a5 95 [2] a3 a0 [2] 8d a0 [2] b2 bc }

  condition:
    any of them
}