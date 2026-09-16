rule TTP_XOR_WriteProcessMemory_1dc1 {
  strings:
    $key_1dc1 = { 4a b3 [2] 78 91 [2] 7e a4 [2] 50 a4 [2] 6f b8 }

  condition:
    any of them
}