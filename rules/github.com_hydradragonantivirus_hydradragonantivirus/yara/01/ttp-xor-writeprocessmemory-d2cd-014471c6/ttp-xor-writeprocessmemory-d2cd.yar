rule TTP_XOR_WriteProcessMemory_d2cd {
  strings:
    $key_d2cd = { 85 bf [2] b7 9d [2] b1 a8 [2] 9f a8 [2] a0 b4 }

  condition:
    any of them
}