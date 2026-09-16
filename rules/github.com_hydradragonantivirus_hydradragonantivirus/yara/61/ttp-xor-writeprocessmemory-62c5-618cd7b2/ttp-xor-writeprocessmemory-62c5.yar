rule TTP_XOR_WriteProcessMemory_62c5 {
  strings:
    $key_62c5 = { 35 b7 [2] 07 95 [2] 01 a0 [2] 2f a0 [2] 10 bc }

  condition:
    any of them
}