rule TTP_XOR_WriteProcessMemory_62c4 {
  strings:
    $key_62c4 = { 35 b6 [2] 07 94 [2] 01 a1 [2] 2f a1 [2] 10 bd }

  condition:
    any of them
}