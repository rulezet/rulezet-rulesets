rule TTP_XOR_WriteProcessMemory_52c1 {
  strings:
    $key_52c1 = { 05 b3 [2] 37 91 [2] 31 a4 [2] 1f a4 [2] 20 b8 }

  condition:
    any of them
}