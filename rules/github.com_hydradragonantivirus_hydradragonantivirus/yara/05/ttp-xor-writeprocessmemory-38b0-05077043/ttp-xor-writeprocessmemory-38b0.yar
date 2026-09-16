rule TTP_XOR_WriteProcessMemory_38b0 {
  strings:
    $key_38b0 = { 6f c2 [2] 5d e0 [2] 5b d5 [2] 75 d5 [2] 4a c9 }

  condition:
    any of them
}