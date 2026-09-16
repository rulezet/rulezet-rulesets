rule TTP_XOR_WriteProcessMemory_62c1 {
  strings:
    $key_62c1 = { 35 b3 [2] 07 91 [2] 01 a4 [2] 2f a4 [2] 10 b8 }

  condition:
    any of them
}