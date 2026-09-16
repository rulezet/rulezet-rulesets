rule TTP_XOR_WriteProcessMemory_2dc1 {
  strings:
    $key_2dc1 = { 7a b3 [2] 48 91 [2] 4e a4 [2] 60 a4 [2] 5f b8 }

  condition:
    any of them
}