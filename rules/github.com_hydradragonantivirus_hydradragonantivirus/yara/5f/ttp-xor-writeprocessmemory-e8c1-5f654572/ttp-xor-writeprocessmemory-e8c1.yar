rule TTP_XOR_WriteProcessMemory_e8c1 {
  strings:
    $key_e8c1 = { bf b3 [2] 8d 91 [2] 8b a4 [2] a5 a4 [2] 9a b8 }

  condition:
    any of them
}