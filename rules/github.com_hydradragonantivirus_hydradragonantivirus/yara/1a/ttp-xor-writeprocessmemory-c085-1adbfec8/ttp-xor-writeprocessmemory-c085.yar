rule TTP_XOR_WriteProcessMemory_c085 {
  strings:
    $key_c085 = { 97 f7 [2] a5 d5 [2] a3 e0 [2] 8d e0 [2] b2 fc }

  condition:
    any of them
}