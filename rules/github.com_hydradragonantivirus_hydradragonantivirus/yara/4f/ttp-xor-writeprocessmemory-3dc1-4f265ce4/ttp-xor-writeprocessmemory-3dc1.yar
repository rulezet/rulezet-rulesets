rule TTP_XOR_WriteProcessMemory_3dc1 {
  strings:
    $key_3dc1 = { 6a b3 [2] 58 91 [2] 5e a4 [2] 70 a4 [2] 4f b8 }

  condition:
    any of them
}