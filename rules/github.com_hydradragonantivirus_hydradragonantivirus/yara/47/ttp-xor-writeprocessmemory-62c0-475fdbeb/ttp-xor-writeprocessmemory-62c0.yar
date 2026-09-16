rule TTP_XOR_WriteProcessMemory_62c0 {
  strings:
    $key_62c0 = { 35 b2 [2] 07 90 [2] 01 a5 [2] 2f a5 [2] 10 b9 }

  condition:
    any of them
}