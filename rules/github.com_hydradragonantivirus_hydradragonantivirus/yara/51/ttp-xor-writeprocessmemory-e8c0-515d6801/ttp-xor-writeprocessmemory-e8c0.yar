rule TTP_XOR_WriteProcessMemory_e8c0 {
  strings:
    $key_e8c0 = { bf b2 [2] 8d 90 [2] 8b a5 [2] a5 a5 [2] 9a b9 }

  condition:
    any of them
}