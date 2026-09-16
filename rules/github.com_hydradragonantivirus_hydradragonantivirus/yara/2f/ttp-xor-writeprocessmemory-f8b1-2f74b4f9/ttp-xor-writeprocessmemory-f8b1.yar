rule TTP_XOR_WriteProcessMemory_f8b1 {
  strings:
    $key_f8b1 = { af c3 [2] 9d e1 [2] 9b d4 [2] b5 d4 [2] 8a c8 }

  condition:
    any of them
}