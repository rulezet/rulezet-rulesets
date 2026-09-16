rule TTP_XOR_WriteProcessMemory_c082 {
  strings:
    $key_c082 = { 97 f0 [2] a5 d2 [2] a3 e7 [2] 8d e7 [2] b2 fb }

  condition:
    any of them
}