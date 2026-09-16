rule TTP_XOR_WriteProcessMemory_72c1 {
  strings:
    $key_72c1 = { 25 b3 [2] 17 91 [2] 11 a4 [2] 3f a4 [2] 00 b8 }

  condition:
    any of them
}