rule TTP_XOR_WriteProcessMemory_c086 {
  strings:
    $key_c086 = { 97 f4 [2] a5 d6 [2] a3 e3 [2] 8d e3 [2] b2 ff }

  condition:
    any of them
}