rule TTP_XOR_WriteProcessMemory_c0c0 {
  strings:
    $key_c0c0 = { 97 b2 [2] a5 90 [2] a3 a5 [2] 8d a5 [2] b2 b9 }

  condition:
    any of them
}